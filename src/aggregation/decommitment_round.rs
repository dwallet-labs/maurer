// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::HashMap;

use commitment::Commitment;
use crypto_bigint::rand_core::CryptoRngCore;
use group::{ComputationalSecuritySizedNumber, GroupElement, PartyID};
use proof::aggregation::DecommitmentRoundParty;
use serde::{Deserialize, Serialize};

use crate::{Error, Result};
use crate::aggregation::proof_share_round;
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
    pub(super) threshold: PartyID,
    pub(super) number_of_parties: PartyID,
    pub(super) language_public_parameters: Language::PublicParameters,
    pub(super) protocol_context: ProtocolContext,
    pub(super) witnesses: Vec<Language::WitnessSpaceGroupElement>,
    pub(super) statements: Vec<Language::StatementSpaceGroupElement>,
    pub(super) randomizers: [Language::WitnessSpaceGroupElement; REPETITIONS],
    pub(super) statement_masks: [Language::StatementSpaceGroupElement; REPETITIONS],
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
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Decommitment, Self::ProofShareRoundParty)> {
        let commitments: HashMap<_, _> = commitments
            .into_iter()
            .filter(|(party_id, _)| *party_id != self.party_id)
            .collect();

        // TODO: is this sufficient? later rounds check against the same party set so this should
        // cover that. TODO: test this
        // if commitments.len() + 1 < self.threshold.into() {
        //     return Err(Error::ThresholdNotReached)?;
        // }

        let decommitment = Decommitment::<REPETITIONS, Language> {
            statements: self
                .statements
                .iter()
                .map(|statement| statement.value())
                .collect(),
            // TODO: take this from previous round instead of computing values again here.
            statement_masks: self
                .statement_masks
                .clone()
                .map(|statement_mask| statement_mask.value()),
            commitment_randomness: self.commitment_randomness,
        };

        let proof_share_round_party =
            proof_share_round::Party::<REPETITIONS, Language, ProtocolContext> {
                party_id: self.party_id,
                threshold: self.threshold,
                number_of_parties: self.number_of_parties,
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