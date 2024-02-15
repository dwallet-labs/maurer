// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::{HashMap, HashSet};

use crypto_bigint::rand_core::CryptoRngCore;
use group::{ComputationalSecuritySizedNumber, PartyID};
use proof::aggregation::DecommitmentRoundParty;
use serde::{Deserialize, Serialize};

use commitment::Commitment;

use crate::aggregation::proof_share_round;
use crate::language;
use crate::{Error, Result};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Decommitment<const REPETITIONS: usize, Language: language::Language<REPETITIONS>> {
    pub(crate) statements: Vec<group::Value<Language::StatementSpaceGroupElement>>,
    #[serde(with = "group::helpers::const_generic_array_serialization")]
    pub(super) statement_masks: [group::Value<Language::StatementSpaceGroupElement>; REPETITIONS],
    pub(super) commitment_randomness: ComputationalSecuritySizedNumber,
}

#[cfg_attr(feature = "test_helpers", derive(Clone))]
#[allow(dead_code)]
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
    pub(super) decommitment: Decommitment<REPETITIONS, Language>,
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
        _commitments: HashMap<PartyID, Self::Commitment>,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Decommitment, Self::ProofShareRoundParty)> {
        todo!()
    }
}
