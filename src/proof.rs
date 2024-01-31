// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::{array, marker::PhantomData};

use crypto_bigint::{ConcatMixed, rand_core::CryptoRngCore, U128};
use group::{ComputationalSecuritySizedNumber, GroupElement, helpers::FlatMapResults, Samplable};
use merlin::Transcript;
use proof::TranscriptProtocol;
use serde::{Deserialize, Serialize};

use crate::{Error, language, Result};
use crate::language::{GroupsPublicParametersAccessors, StatementSpaceValue, WitnessSpaceValue};

/// The number of repetitions used for sound Maurer proofs, i.e. proofs that achieve negligible soundness error.
pub const SOUND_PROOFS_REPETITIONS: usize = 1;

/// The number of repetitions used for Maurer proofs that achieve 1/2 soundness error.
pub const BIT_SOUNDNESS_PROOFS_REPETITIONS: usize = ComputationalSecuritySizedNumber::BITS;

// For a batch size $N_B$, the challenge space should be $[0,N_B \cdot 2^{\kappa + 2})$.
// Setting it to be 128-bit larger than the computational security parameter $\kappa$ allows us to
// use any batch size (Rust does not allow a vector larger than $2^64$ elements,
// as does 64-bit architectures in which the memory won't even be addressable.)
pub(super) type ChallengeSizedNumber =
<ComputationalSecuritySizedNumber as ConcatMixed<U128>>::MixedOutput;

/// A Batched Maurer Zero-Knowledge Proof.
/// Implements Appendix B. Maurer Protocols in the paper.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Proof<
    // Number of parallel repetitions required to get a negligible soundness error.
    const REPETITIONS: usize,
    // The language we are proving
    Language: language::Language<REPETITIONS>,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
    ProtocolContext: Clone,
> {
    #[serde(with = "group::helpers::const_generic_array_serialization")]
    pub(super) statement_masks: [StatementSpaceValue<REPETITIONS, Language>; REPETITIONS],
    #[serde(with = "group::helpers::const_generic_array_serialization")]
    pub(super) responses: [WitnessSpaceValue<REPETITIONS, Language>; REPETITIONS],

    _protocol_context_choice: PhantomData<ProtocolContext>,
}

impl<
    const REPETITIONS: usize,
    Language: language::Language<REPETITIONS>,
    ProtocolContext: Clone + Serialize,
> Proof<REPETITIONS, Language, ProtocolContext>
{
    pub(super) fn new(
        statement_masks: [group::Value<Language::StatementSpaceGroupElement>; REPETITIONS],
        responses: [group::Value<Language::WitnessSpaceGroupElement>; REPETITIONS],
    ) -> Self {
        Self {
            statement_masks,
            responses,
            _protocol_context_choice: PhantomData,
        }
    }

    /// Prove a batched Maurer zero-knowledge claim.
    /// Returns the zero-knowledge proof.
    pub fn prove(
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        witnesses: Vec<Language::WitnessSpaceGroupElement>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self, Vec<Language::StatementSpaceGroupElement>)> {
        let statements: Result<Vec<Language::StatementSpaceGroupElement>> = witnesses
            .iter()
            .map(|witness| Language::homomorphose(witness, language_public_parameters))
            .collect();
        let statements = statements?;

        Self::prove_with_statements(
            protocol_context,
            language_public_parameters,
            witnesses,
            statements.clone(),
            rng,
        )
            .map(|proof| (proof, statements))
    }

    /// Prove a batched Maurer zero-knowledge claim.
    /// Returns the zero-knowledge proof.
    ///
    /// An inner function to be used when the randomizers should be sampled from a sub-domain.
    /// Unless that is the case, use ['Self::prove'].
    pub fn prove_with_randomizers(
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        witnesses: Vec<Language::WitnessSpaceGroupElement>,
        randomizers: [Language::WitnessSpaceGroupElement; REPETITIONS],
        statement_masks: [Language::StatementSpaceGroupElement; REPETITIONS],
    ) -> Result<(Self, Vec<Language::StatementSpaceGroupElement>)> {
        let statements: Result<Vec<Language::StatementSpaceGroupElement>> = witnesses
            .iter()
            .map(|witness| Language::homomorphose(witness, language_public_parameters))
            .collect();
        let statements = statements?;

        Self::prove_inner(
            protocol_context,
            language_public_parameters,
            witnesses,
            statements.clone(),
            randomizers,
            statement_masks,
        )
            .map(|proof| (proof, statements))
    }

    pub(super) fn prove_with_statements(
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        witnesses: Vec<Language::WitnessSpaceGroupElement>,
        statements: Vec<Language::StatementSpaceGroupElement>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let (randomizers, statement_masks) =
            Self::sample_randomizers_and_statement_masks(language_public_parameters, rng)?;

        Self::prove_inner(
            protocol_context,
            language_public_parameters,
            witnesses,
            statements,
            randomizers,
            statement_masks,
        )
    }

    pub(super) fn prove_inner(
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        witnesses: Vec<Language::WitnessSpaceGroupElement>,
        statements: Vec<Language::StatementSpaceGroupElement>,
        randomizers: [Language::WitnessSpaceGroupElement; REPETITIONS],
        statement_masks: [Language::StatementSpaceGroupElement; REPETITIONS],
    ) -> Result<Self> {
        if witnesses.is_empty() {
            return Err(Error::InvalidParameters);
        }

        let batch_size = witnesses.len();

        let statement_masks_values = statement_masks
            .clone()
            .map(|statement_mask| statement_mask.value());

        let mut transcript = Self::setup_transcript(
            protocol_context,
            language_public_parameters,
            statements
                .iter()
                .map(|statement| statement.value())
                .collect(),
            &statement_masks_values,
        )?;

        let challenges: [Vec<ChallengeSizedNumber>; REPETITIONS] =
            Self::compute_challenges(batch_size, &mut transcript);

        let challenge_bit_size = Language::challenge_bits(batch_size)?;
        let responses = randomizers
            .into_iter()
            .zip(challenges)
            .map(|(randomizer, challenges)| {
                witnesses
                    .clone()
                    .into_iter()
                    .zip(challenges)
                    .filter_map(|(witness, challenge)| {
                        if challenge_bit_size == 1 {
                            // A special case that needs special caring.
                            if challenge == ChallengeSizedNumber::ZERO {
                                None
                            } else {
                                Some(witness)
                            }
                        } else {
                            // Using the "small exponents" method for batching.
                            Some(witness.scalar_mul_bounded(&challenge, challenge_bit_size))
                        }
                    })
                    .reduce(|a, b| a + b)
                    .map_or(
                        randomizer.clone(),
                        |witnesses_and_challenges_linear_combination| {
                            randomizer + witnesses_and_challenges_linear_combination
                        },
                    ).value()
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| crate::Error::InternalError)?;

        Ok(Self::new(statement_masks_values, responses))
    }

    /// Verify a batched Maurer zero-knowledge proof.
    ///

    pub fn verify(
        &self,
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        statements: Vec<Language::StatementSpaceGroupElement>,
    ) -> Result<()> {
        let mut transcript = Self::setup_transcript(
            protocol_context,
            language_public_parameters,
            statements
                .iter()
                .map(|statement| statement.value())
                .collect(),
            &self.statement_masks,
        )?;

        self.verify_inner(&mut transcript, language_public_parameters, statements)
    }

    pub(crate) fn verify_inner(
        &self,
        transcript: &mut Transcript,
        language_public_parameters: &Language::PublicParameters,
        statements: Vec<Language::StatementSpaceGroupElement>,
    ) -> Result<()> {
        let batch_size = statements.len();

        let challenges: [Vec<ChallengeSizedNumber>; REPETITIONS] =
            Self::compute_challenges(batch_size, transcript);

        let responses = self
            .responses
            .map(|response| {
                Language::WitnessSpaceGroupElement::new(
                    response,
                    language_public_parameters.witness_space_public_parameters(),
                )
            })
            .flat_map_results()?;

        let statement_masks = self
            .statement_masks
            .map(|statement_mask| {
                Language::StatementSpaceGroupElement::new(
                    statement_mask,
                    language_public_parameters.statement_space_public_parameters(),
                )
            })
            .flat_map_results()?;

        let response_statements: [Language::StatementSpaceGroupElement; REPETITIONS] = responses
            .map(|response| Language::homomorphose(&response, language_public_parameters))
            .flat_map_results()?;

        let challenge_bit_size = Language::challenge_bits(batch_size)?;
        let reconstructed_response_statements: [Language::StatementSpaceGroupElement; REPETITIONS] =
            statement_masks
                .into_iter()
                .zip(challenges)
                .map(|(statement_mask, challenges)| {
                    statements
                        .clone()
                        .into_iter()
                        .zip(challenges)
                        .filter_map(|(statement, challenge)| {
                            if challenge_bit_size == 1 {
                                // A special case that needs special caring
                                if challenge == ChallengeSizedNumber::ZERO {
                                    None
                                } else {
                                    Some(statement)
                                }
                            } else {
                                Some(statement.scalar_mul_bounded(&challenge, challenge_bit_size))
                            }
                        })
                        .reduce(|a, b| a + b)
                        .map_or(
                            statement_mask.clone(),
                            |statements_and_challenges_linear_combination| {
                                statement_mask + statements_and_challenges_linear_combination
                            },
                        )
                })
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| Error::InternalError)?;

        if response_statements == reconstructed_response_statements {
            return Ok(());
        }
        Err(proof::Error::ProofVerification)?
    }

    pub(super) fn sample_randomizers_and_statement_masks(
        language_public_parameters: &Language::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(
        [Language::WitnessSpaceGroupElement; REPETITIONS],
        [Language::StatementSpaceGroupElement; REPETITIONS],
    )> {
        let randomizers = array::from_fn(|_| {
            Language::WitnessSpaceGroupElement::sample(
                language_public_parameters.witness_space_public_parameters(),
                rng,
            )
        })
            .flat_map_results()?;

        let statement_masks = randomizers
            .clone()
            .map(|randomizer| Language::homomorphose(&randomizer, language_public_parameters))
            .flat_map_results()?;

        Ok((randomizers, statement_masks))
    }

    pub(super) fn setup_transcript(
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        statements: Vec<group::Value<Language::StatementSpaceGroupElement>>,
        statement_masks_values: &[group::Value<Language::StatementSpaceGroupElement>; REPETITIONS],
    ) -> Result<Transcript> {
        let mut transcript = Transcript::new(Language::NAME.as_bytes());

        transcript.serialize_to_transcript_as_json(b"protocol context", protocol_context)?;

        transcript.serialize_to_transcript_as_json(
            b"language public parameters",
            language_public_parameters,
        )?;

        transcript.serialize_to_transcript_as_json(
            b"witness space public parameters",
            language_public_parameters.witness_space_public_parameters(),
        )?;

        transcript.serialize_to_transcript_as_json(
            b"statement space public parameters",
            language_public_parameters.statement_space_public_parameters(),
        )?;

        if statements.iter().any(|statement| {
            transcript
                .serialize_to_transcript_as_json(b"statement value", &statement)
                .is_err()
        }) {
            return Err(Error::InvalidParameters);
        }

        if statement_masks_values.iter().any(|statement_mask| {
            transcript
                .serialize_to_transcript_as_json(b"statement mask value", &statement_mask)
                .is_err()
        }) {
            return Err(Error::InvalidParameters);
        }

        Ok(transcript)
    }

    fn compute_challenges(
        batch_size: usize,
        transcript: &mut Transcript,
    ) -> [Vec<ChallengeSizedNumber>; REPETITIONS] {
        array::from_fn(|_| {
            (1..=batch_size)
                .map(|_| {
                    let challenge = transcript.challenge(b"challenge");

                    // we don't have to do this because Merlin uses a PRF behind the scenes,
                    // but we do it anyways as a security best-practice
                    transcript.append_uint(b"challenge", &challenge);

                    challenge
                })
                .collect()
        })
    }
}