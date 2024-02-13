// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::{HashMap, HashSet};

use crypto_bigint::rand_core::CryptoRngCore;
use group::PartyID;
use proof::aggregation::ProofAggregationRoundParty;
use serde::Serialize;

use crate::aggregation::proof_share_round::ProofShare;
use crate::aggregation::Output;
use crate::{Error, Result};

#[cfg_attr(feature = "test_helpers", derive(Clone))]
#[allow(dead_code)]
pub struct Party<
    // Number of times this proof should be repeated to achieve sufficient security.
    const REPETITIONS: usize,
    // The language we are proving.
    Language: crate::Language<REPETITIONS>,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript.
    ProtocolContext: Clone,
> {
    pub(super) party_id: PartyID,
    pub(crate) provers: HashSet<PartyID>,
    pub(super) language_public_parameters: Language::PublicParameters,
    pub(super) protocol_context: ProtocolContext,
    pub(super) statement_masks:
        HashMap<PartyID, [group::Value<Language::StatementSpaceGroupElement>; REPETITIONS]>,
    pub(super) statements: HashMap<PartyID, Vec<Language::StatementSpaceGroupElement>>,
    pub(super) aggregated_statements: Vec<Language::StatementSpaceGroupElement>,
    pub(super) aggregated_statement_masks: [Language::StatementSpaceGroupElement; REPETITIONS],
    pub(super) responses: [Language::WitnessSpaceGroupElement; REPETITIONS],
}

impl<
        const REPETITIONS: usize,
        Language: crate::Language<REPETITIONS>,
        ProtocolContext: Clone + Serialize,
    > ProofAggregationRoundParty<Output<REPETITIONS, Language, ProtocolContext>>
    for Party<REPETITIONS, Language, ProtocolContext>
{
    type Error = Error;
    type ProofShare = ProofShare<REPETITIONS, Language>;

    fn aggregate_proof_shares(
        self,
        _proof_shares: HashMap<PartyID, Self::ProofShare>,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<Output<REPETITIONS, Language, ProtocolContext>> {
        todo!()
    }
}
