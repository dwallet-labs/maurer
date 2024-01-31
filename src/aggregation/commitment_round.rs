// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use commitment::Commitment;
use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::Random;
use group::{ComputationalSecuritySizedNumber, GroupElement, PartyID};
use proof::aggregation::CommitmentRoundParty;
use serde::Serialize;

use crate::{language, Proof};
use crate::{Error, Result};
use crate::aggregation::decommitment_round;

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
    pub(crate) party_id: PartyID,
    pub(crate) threshold: PartyID,
    pub(crate) number_of_parties: PartyID,
    pub(crate) language_public_parameters: Language::PublicParameters,
    pub(crate) protocol_context: ProtocolContext,
    pub(crate) witnesses: Vec<Language::WitnessSpaceGroupElement>,
    pub(super) randomizers: [Language::WitnessSpaceGroupElement; REPETITIONS],
    pub(super) statement_masks: [Language::StatementSpaceGroupElement; REPETITIONS],
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
        let statements: Result<Vec<Language::StatementSpaceGroupElement>> = self
            .witnesses
            .iter()
            .map(|witness| Language::homomorphose(witness, &self.language_public_parameters))
            .collect();
        let statements = statements?;

        let commitment_randomness = ComputationalSecuritySizedNumber::random(rng);

        let mut transcript = Proof::<REPETITIONS, Language, ProtocolContext>::setup_transcript(
            &self.protocol_context,
            &self.language_public_parameters,
            statements
                .iter()
                .map(|statement| statement.value())
                .collect(),
            &self
                .statement_masks
                .clone()
                .map(|statement_mask| statement_mask.value()),
        )?;

        let commitment = Commitment::commit_transcript(&mut transcript, &commitment_randomness);

        let decommitment_round_party =
            decommitment_round::Party::<REPETITIONS, Language, ProtocolContext> {
                party_id: self.party_id,
                threshold: self.threshold,
                number_of_parties: self.number_of_parties,
                language_public_parameters: self.language_public_parameters,
                protocol_context: self.protocol_context,
                witnesses: self.witnesses,
                statements,
                randomizers: self.randomizers,
                statement_masks: self.statement_masks,
                commitment_randomness,
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
        threshold: PartyID,
        number_of_parties: PartyID,
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
            threshold,
            number_of_parties,
            language_public_parameters,
            protocol_context,
            witnesses,
            randomizers,
            statement_masks,
        })
    }
}
