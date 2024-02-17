// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::aggregation::decommitment_round;
use crate::aggregation::decommitment_round::Decommitment;
use crate::{language, Proof};
use crate::{Error, Result};
use commitment::Commitment;
use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::Random;
use group::{ComputationalSecuritySizedNumber, GroupElement, PartyID};
use proof::aggregation;
use proof::aggregation::CommitmentRoundParty;
use serde::Serialize;
use std::collections::HashSet;

#[cfg_attr(any(test, feature = "test_helpers"), derive(Clone))]
pub struct Party<
    // Number of times this proof should be repeated to achieve sufficient security.
    const REPETITIONS: usize,
    // The language we are proving
    Language: language::Language<REPETITIONS>,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript.
    ProtocolContext: Clone,
> {
    pub party_id: PartyID,
    // The set of parties ${P_i}$ participating in the proof aggregation protocol.
    pub provers: HashSet<PartyID>,
    pub language_public_parameters: Language::PublicParameters,
    pub protocol_context: ProtocolContext,
    pub witnesses: Vec<Language::WitnessSpaceGroupElement>,
    pub randomizers: [Language::WitnessSpaceGroupElement; REPETITIONS],
    pub statement_masks: [Language::StatementSpaceGroupElement; REPETITIONS],
}

impl<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
        ProtocolContext: Clone + Serialize,
    > CommitmentRoundParty<super::Output<REPETITIONS, Language, ProtocolContext>>
    for Party<REPETITIONS, Language, ProtocolContext>
{
    type Error = Error;
    type Commitment = Commitment;

    type DecommitmentRoundParty = decommitment_round::Party<REPETITIONS, Language, ProtocolContext>;

    fn commit_statements_and_statement_mask(
        self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Commitment, Self::DecommitmentRoundParty)> {
        if !self.provers.contains(&self.party_id) {
            return Err(Error::Aggregation(
                aggregation::Error::NonParticipatingParty,
            ));
        }

        let statements: Result<Vec<Language::StatementSpaceGroupElement>> = self
            .witnesses
            .iter()
            .map(|witness| Language::homomorphose(witness, &self.language_public_parameters))
            .collect();
        let statements = statements?;

        let commitment_randomness = ComputationalSecuritySizedNumber::random(rng);

        let statement_masks_values =
            Language::StatementSpaceGroupElement::batch_normalize_const_generic(
                self.statement_masks.clone(),
            );

        let statements_values =
            Language::StatementSpaceGroupElement::batch_normalize(statements.clone());

        let mut transcript = Proof::<REPETITIONS, Language, ProtocolContext>::setup_transcript(
            &self.protocol_context,
            &self.language_public_parameters,
            statements_values.clone(),
            &statement_masks_values,
        )?;

        let commitment = Commitment::commit_transcript(
            self.party_id,
            COMMITMENT_LABEL.to_string(),
            &mut transcript,
            &commitment_randomness,
        );

        let decommitment = Decommitment::<REPETITIONS, Language> {
            statements: statements_values,
            statement_masks: statement_masks_values,
            commitment_randomness,
        };

        let decommitment_round_party =
            decommitment_round::Party::<REPETITIONS, Language, ProtocolContext> {
                party_id: self.party_id,
                provers: self.provers,
                language_public_parameters: self.language_public_parameters,
                protocol_context: self.protocol_context,
                witnesses: self.witnesses,
                statements,
                randomizers: self.randomizers,
                statement_masks: self.statement_masks,
                decommitment,
            };

        Ok((commitment, decommitment_round_party))
    }
}

impl<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
        ProtocolContext: Clone + Serialize,
    > Party<REPETITIONS, Language, ProtocolContext>
{
    pub fn new_session(
        party_id: PartyID,
        provers: HashSet<PartyID>,
        language_public_parameters: Language::PublicParameters,
        protocol_context: ProtocolContext,
        witnesses: Vec<Language::WitnessSpaceGroupElement>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let (randomizers, statement_masks) = Proof::<
            REPETITIONS,
            Language,
            ProtocolContext,
        >::sample_randomizers_and_statement_masks(
            &language_public_parameters, rng,
        )?;

        Ok(Self {
            party_id,
            provers,
            language_public_parameters,
            protocol_context,
            witnesses,
            randomizers,
            statement_masks,
        })
    }
}

pub(super) const COMMITMENT_LABEL: &str = "maurer proof aggregation - commitment round commitment";
