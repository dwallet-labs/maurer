// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::{HashMap, HashSet};

use crypto_bigint::rand_core::CryptoRngCore;
use group::PartyID;
use proof::aggregation::ProofShareRoundParty;
use serde::{Deserialize, Serialize};

use commitment::Commitment;

use crate::aggregation::decommitment_round::Decommitment;
use crate::aggregation::proof_aggregation_round;
use crate::language::WitnessSpaceValue;
use crate::{Error, Result};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProofShare<const REPETITIONS: usize, Language: crate::Language<REPETITIONS>>(
    #[serde(with = "group::helpers::const_generic_array_serialization")]
    pub(super)  [WitnessSpaceValue<REPETITIONS, Language>; REPETITIONS],
);

#[cfg_attr(feature = "test_helpers", derive(Clone))]
#[allow(dead_code)]
pub struct Party<
    // Number of times this proof should be repeated to achieve sufficient security
    const REPETITIONS: usize,
    // The language we are proving
    Language: crate::Language<REPETITIONS>,
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
    pub(super) commitments: HashMap<PartyID, Commitment>,
}

impl<
        const REPETITIONS: usize,
        Language: crate::Language<REPETITIONS>,
        ProtocolContext: Clone + Serialize,
    > ProofShareRoundParty<super::Output<REPETITIONS, Language, ProtocolContext>>
    for Party<REPETITIONS, Language, ProtocolContext>
{
    type Error = Error;
    type Decommitment = Decommitment<REPETITIONS, Language>;
    type ProofShare = ProofShare<REPETITIONS, Language>;
    type ProofAggregationRoundParty =
        proof_aggregation_round::Party<REPETITIONS, Language, ProtocolContext>;

    fn generate_proof_share(
        self,
        _decommitments: HashMap<PartyID, Self::Decommitment>,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ProofShare, Self::ProofAggregationRoundParty)> {
        todo!()
    }
}
