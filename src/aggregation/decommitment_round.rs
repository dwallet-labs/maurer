// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::{HashMap, HashSet};

use commitment::Commitment;
use crypto_bigint::rand_core::CryptoRngCore;
use group::{ComputationalSecuritySizedNumber, GroupElement, PartyID};
use proof::aggregation::DecommitmentRoundParty;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};
use crate::aggregation::{process_incoming_messages, proof_share_round};
use crate::language;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Decommitment<const REPETITIONS: usize, Language: language::Language<REPETITIONS>> {
    pub(crate) statements: Vec<group::Value<Language::StatementSpaceGroupElement>>,
    #[serde(with = "group::helpers::const_generic_array_serialization")]
    pub(super) statement_masks: [group::Value<Language::StatementSpaceGroupElement>; REPETITIONS],
    pub(super) commitment_randomness: ComputationalSecuritySizedNumber,
}

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    // Number of times this proof should be repeated to achieve sufficient security
    const REPETITIONS: usize,
    // The language we are proving
    Language: language::Language<REPETITIONS>,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
    ProtocolContext: Clone,
> {
    pub(super) party_id: PartyID,
    pub(crate) provers: HashSet<PartyID>,
    pub(super) language_public_parameters: Language::PublicParameters,
    pub(super) protocol_context: ProtocolContext,
    pub(super) witnesses: Vec<Language::WitnessSpaceGroupElement>,
    pub(super) statements: Vec<Language::StatementSpaceGroupElement>,
    pub(super) randomizers: [Language::WitnessSpaceGroupElement; REPETITIONS],
    pub(super) statement_masks: [Language::StatementSpaceGroupElement; REPETITIONS],
    pub(super) statement_masks_values: [group::Value<Language::StatementSpaceGroupElement>; REPETITIONS],
    pub(super) commitment_randomness: ComputationalSecuritySizedNumber,
}


impl<
    const REPETITIONS: usize,
    Language: language::Language<REPETITIONS>,
    ProtocolContext: Clone + Serialize,
> DecommitmentRoundParty<super::Output<REPETITIONS, Language, ProtocolContext>>
for Party<REPETITIONS, Language, ProtocolContext>
{
    type Error = Error;
    type Commitment = Commitment;
    type Decommitment = Decommitment<REPETITIONS, Language>;
    type ProofShareRoundParty = proof_share_round::Party<REPETITIONS, Language, ProtocolContext>;

    fn decommit_statements_and_statement_mask(
        self,
        commitments: HashMap<PartyID, Self::Commitment>,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Decommitment, Self::ProofShareRoundParty)> {
        let commitments = process_incoming_messages(self.party_id, &self.provers, commitments)?;

        let decommitment = Decommitment::<REPETITIONS, Language> {
            statements: self
                .statements
                .iter()
                .map(|statement| statement.value())
                .collect(),
            statement_masks: self
                .statement_masks_values,
            commitment_randomness: self.commitment_randomness,
        };

        let proof_share_round_party =
            proof_share_round::Party::<REPETITIONS, Language, ProtocolContext> {
                party_id: self.party_id,
                provers: self.provers,
                language_public_parameters: self.language_public_parameters,
                protocol_context: self.protocol_context,
                witnesses: self.witnesses,
                statements: self.statements,
                randomizers: self.randomizers,
                statement_masks: self.statement_masks,
                commitments,
            };

        Ok((decommitment, proof_share_round_party))
    }
}
