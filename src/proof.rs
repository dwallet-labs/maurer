// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub mod fischlin;

use crypto_bigint::rand_core::CryptoRngCore;
use group::{helpers::FlatMapResults, ComputationalSecuritySizedNumber, GroupElement, Samplable};
use merlin::Transcript;
use proof::TranscriptProtocol;
use serde::{Deserialize, Serialize};
use std::{array, marker::PhantomData};

use crate::{
    language,
    language::{GroupsPublicParametersAccessors, StatementSpaceValue, WitnessSpaceValue},
    Error, Result,
};

/// The number of repetitions used for sound Maurer proofs, i.e., proofs that achieve negligible
/// soundness error.
pub const SOUND_PROOFS_REPETITIONS: usize = 1;

/// The number of repetitions used for Maurer proofs that achieve 1/2 soundness error.
pub const BIT_SOUNDNESS_PROOFS_REPETITIONS: usize = ComputationalSecuritySizedNumber::BITS;

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
    pub statement_masks: [StatementSpaceValue<REPETITIONS, Language>; REPETITIONS],
    #[serde(with = "group::helpers::const_generic_array_serialization")]
    pub responses: [WitnessSpaceValue<REPETITIONS, Language>; REPETITIONS],

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
    /// An inner function to be used when the randomizers should be sampled from a subdomain.
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

        let statement_masks_values =
            Language::StatementSpaceGroupElement::batch_normalize_const_generic(statement_masks);

        let statements_values =
            Language::StatementSpaceGroupElement::batch_normalize(statements.clone());

        let mut transcript = Self::setup_transcript(
            protocol_context,
            language_public_parameters,
            statements_values,
            &statement_masks_values,
        )?;

        let challenges: [Vec<ComputationalSecuritySizedNumber>; REPETITIONS] =
            Self::compute_challenges(batch_size, &mut transcript);

        let challenge_bit_size = Language::challenge_bits()?;
        let responses = Language::WitnessSpaceGroupElement::batch_normalize_const_generic(
            randomizers
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
                                if challenge == ComputationalSecuritySizedNumber::ZERO {
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
                        )
                })
                .collect::<Vec<_>>()
                .try_into()
                .map_err(|_| Error::InternalError)?,
        );

        Ok(Self::new(statement_masks_values, responses))
    }

    /// Verify a batched Maurer zero-knowledge proof.
    pub fn verify(
        &self,
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        statements: Vec<Language::StatementSpaceGroupElement>,
    ) -> Result<()> {
        let mut transcript = Self::setup_transcript(
            protocol_context,
            language_public_parameters,
            Language::StatementSpaceGroupElement::batch_normalize(statements.clone()),
            &self.statement_masks,
        )?;

        let challenges: [Vec<ComputationalSecuritySizedNumber>; REPETITIONS] =
            Self::compute_challenges(statements.len(), &mut transcript);

        self.verify_inner(challenges, language_public_parameters, statements)
    }

    #[allow(unused)]
    fn verify_with_transcript(
        &self,
        transcript: &mut Transcript,
        language_public_parameters: &Language::PublicParameters,
        statements: Vec<Language::StatementSpaceGroupElement>,
    ) -> Result<()> {
        let challenges: [Vec<ComputationalSecuritySizedNumber>; REPETITIONS] =
            Self::compute_challenges(statements.len(), transcript);

        self.verify_inner(challenges, language_public_parameters, statements)
    }

    pub(crate) fn verify_inner(
        &self,
        challenges: [Vec<ComputationalSecuritySizedNumber>; REPETITIONS],
        language_public_parameters: &Language::PublicParameters,
        statements: Vec<Language::StatementSpaceGroupElement>,
    ) -> Result<()> {
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

        let challenge_bit_size = Language::challenge_bits()?;
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
                                if challenge == ComputationalSecuritySizedNumber::ZERO {
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

    #[allow(clippy::type_complexity)]
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

    pub(crate) fn compute_challenges(
        batch_size: usize,
        transcript: &mut Transcript,
    ) -> [Vec<ComputationalSecuritySizedNumber>; REPETITIONS] {
        array::from_fn(|_| {
            (1..=batch_size)
                .map(|_| {
                    let challenge = transcript.challenge(b"challenge");

                    // we don't have to do this because Merlin uses a PRF behind the scenes,
                    // but we do it anyway as a security best-practice
                    transcript.append_uint(b"challenge", &challenge);

                    challenge
                })
                .collect()
        })
    }
}

// These tests helpers can be used for different `group` implementations,
// therefore they need to be exported.
// Since exporting rust `#[cfg(test)]` is impossible, they exist in a dedicated feature-gated module.
#[cfg(any(test, feature = "benchmarking"))]
#[allow(unused_imports)]
pub(super) mod test_helpers {
    use std::marker::PhantomData;

    use criterion::measurement::{Measurement, WallTime};
    use rand_core::OsRng;

    use super::*;
    use crate::test_helpers::{sample_witness, sample_witnesses};

    pub fn generate_valid_proof<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
    >(
        language_public_parameters: &Language::PublicParameters,
        witnesses: Vec<Language::WitnessSpaceGroupElement>,
        rng: &mut impl CryptoRngCore,
    ) -> (
        Proof<REPETITIONS, Language, PhantomData<()>>,
        Vec<Language::StatementSpaceGroupElement>,
    ) {
        Proof::prove(&PhantomData, language_public_parameters, witnesses, rng).unwrap()
    }

    pub fn valid_proof_verifies<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
    >(
        language_public_parameters: &Language::PublicParameters,
        batch_size: usize,
        rng: &mut impl CryptoRngCore,
    ) {
        let witnesses =
            sample_witnesses::<REPETITIONS, Language>(language_public_parameters, batch_size, rng);

        valid_proof_verifies_internal::<REPETITIONS, Language>(
            language_public_parameters,
            witnesses,
            rng,
        )
    }

    pub fn valid_proof_verifies_internal<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
    >(
        language_public_parameters: &Language::PublicParameters,
        witnesses: Vec<Language::WitnessSpaceGroupElement>,
        rng: &mut impl CryptoRngCore,
    ) {
        let (proof, statements) = generate_valid_proof::<REPETITIONS, Language>(
            language_public_parameters,
            witnesses.clone(),
            rng,
        );

        assert!(
            proof
                .verify(&PhantomData, language_public_parameters, statements)
                .is_ok(),
            "valid proofs should verify"
        );
    }

    pub fn invalid_proof_fails_verification<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
    >(
        invalid_witness_space_value: Option<WitnessSpaceValue<REPETITIONS, Language>>,
        invalid_statement_space_value: Option<StatementSpaceValue<REPETITIONS, Language>>,
        language_public_parameters: &Language::PublicParameters,
        batch_size: usize,
        rng: &mut impl CryptoRngCore,
    ) {
        let witnesses =
            sample_witnesses::<REPETITIONS, Language>(language_public_parameters, batch_size, rng);

        let (valid_proof, statements) = generate_valid_proof::<REPETITIONS, Language>(
            language_public_parameters,
            witnesses.clone(),
            rng,
        );

        let wrong_witness =
            sample_witness::<REPETITIONS, Language>(language_public_parameters, rng);

        let wrong_statement =
            Language::homomorphose(&wrong_witness, language_public_parameters).unwrap();

        assert!(
            matches!(
                valid_proof
                    .verify(
                        &PhantomData,
                        language_public_parameters,
                        statements
                            .clone()
                            .into_iter()
                            .take(batch_size - 1)
                            .chain(vec![wrong_statement.clone()])
                            .collect(),
                    )
                    .err()
                    .unwrap(),
                Error::Proof(proof::Error::ProofVerification)
            ),
            "valid proof shouldn't verify against wrong statements"
        );

        let mut invalid_proof = valid_proof.clone();
        invalid_proof.responses = [wrong_witness.value(); REPETITIONS];

        assert!(
            matches!(
                invalid_proof
                    .verify(&PhantomData, language_public_parameters, statements.clone(),)
                    .err()
                    .unwrap(),
                Error::Proof(proof::Error::ProofVerification)
            ),
            "proof with a wrong response shouldn't pass verification"
        );

        let mut invalid_proof = valid_proof.clone();
        invalid_proof.statement_masks = [wrong_statement.neutral().value(); REPETITIONS];

        assert!(
            matches!(
                invalid_proof
                    .verify(&PhantomData, language_public_parameters, statements.clone(),)
                    .err()
                    .unwrap(),
                Error::Proof(proof::Error::ProofVerification)
            ),
            "proof with a neutral statement_mask shouldn't pass verification"
        );

        let mut invalid_proof = valid_proof.clone();
        invalid_proof.responses = [wrong_witness.neutral().value(); REPETITIONS];

        assert!(
            matches!(
                invalid_proof
                    .verify(&PhantomData, language_public_parameters, statements.clone(),)
                    .err()
                    .unwrap(),
                Error::Proof(proof::Error::ProofVerification)
            ),
            "proof with a neutral response shouldn't pass verification"
        );

        if let Some(invalid_statement_space_value) = invalid_statement_space_value {
            let mut invalid_proof = valid_proof.clone();
            invalid_proof.statement_masks = [invalid_statement_space_value; REPETITIONS];

            assert!(matches!(
            invalid_proof
                .verify(
                    &PhantomData,
                    language_public_parameters,
                    statements.clone(),
                )
                .err()
                .unwrap(),
            Error::GroupInstantiation(group::Error::InvalidGroupElement)),
                    "proof with an invalid statement_mask value should generate an invalid parameter error when checking the element is not in the group"
            );
        }

        if let Some(invalid_witness_space_value) = invalid_witness_space_value {
            let mut invalid_proof = valid_proof.clone();
            invalid_proof.responses = [invalid_witness_space_value; REPETITIONS];

            assert!(matches!(
            invalid_proof
                .verify(
                    &PhantomData,
                    language_public_parameters,
                    statements.clone(),
                )
                .err()
                .unwrap(),
            Error::GroupInstantiation(group::Error::InvalidGroupElement)),
                    "proof with an invalid response value should generate an invalid parameter error when checking the element is not in the group"
            );
        }
    }

    /// Simulates a malicious prover that tries to trick an honest verifier by proving a statement
    /// over wrong public parameters.
    pub fn proof_over_invalid_public_parameters_fails_verification<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
    >(
        prover_language_public_parameters: &Language::PublicParameters,
        verifier_language_public_parameters: &Language::PublicParameters,
        batch_size: usize,
        rng: &mut impl CryptoRngCore,
    ) {
        let witnesses = sample_witnesses::<REPETITIONS, Language>(
            verifier_language_public_parameters,
            batch_size,
            rng,
        );

        let (proof, statements) = generate_valid_proof::<REPETITIONS, Language>(
            prover_language_public_parameters,
            witnesses,
            rng,
        );

        assert!(
            matches!(
                proof
                    .verify(
                        &PhantomData,
                        verifier_language_public_parameters,
                        statements,
                    )
                    .err()
                    .unwrap(),
                Error::Proof(proof::Error::ProofVerification)
            ),
            "proof over wrong public parameters shouldn't pass verification"
        );
    }

    fn setup_partial_transcript<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
        ProtocolContext: Serialize,
    >(
        language_name: bool,
        protocol_context: Option<ProtocolContext>,
        language_public_parameters: Option<Language::PublicParameters>,
        statements: Option<Vec<group::Value<Language::StatementSpaceGroupElement>>>,
        statement_masks_values: Option<
            [group::Value<Language::StatementSpaceGroupElement>; REPETITIONS],
        >,
    ) -> Transcript {
        let mut transcript = if language_name {
            Transcript::new(Language::NAME.as_bytes())
        } else {
            Transcript::new("".as_bytes())
        };

        if let Some(protocol_context) = protocol_context {
            transcript
                .serialize_to_transcript_as_json(b"protocol context", &protocol_context)
                .unwrap()
        }

        language_public_parameters.map(|language_public_parameters| {
            transcript
                .serialize_to_transcript_as_json(
                    b"language public parameters",
                    &language_public_parameters,
                )
                .unwrap();

            transcript
                .serialize_to_transcript_as_json(
                    b"witness space public parameters",
                    &language_public_parameters.witness_space_public_parameters(),
                )
                .unwrap();

            transcript.serialize_to_transcript_as_json(
                b"statement space public parameters",
                &language_public_parameters.statement_space_public_parameters(),
            )
        });

        if let Some(statements) = statements {
            statements.iter().for_each(|statement| {
                transcript
                    .serialize_to_transcript_as_json(b"statement value", &statement)
                    .unwrap()
            })
        }

        if let Some(statement_masks) = statement_masks_values {
            statement_masks.iter().for_each(|statement_mask| {
                transcript
                    .serialize_to_transcript_as_json(b"statement mask value", &statement_mask)
                    .unwrap()
            })
        }

        transcript
    }

    /// Test weak Fiat-Shamir attacks.
    pub fn proof_with_incomplete_transcript_fails<
        const REPETITIONS: usize,
        Language: language::Language<REPETITIONS>,
    >(
        language_public_parameters: &Language::PublicParameters,
        batch_size: usize,
        rng: &mut impl CryptoRngCore,
    ) {
        let witnesses =
            sample_witnesses::<REPETITIONS, Language>(language_public_parameters, batch_size, rng);
        let protocol_context = "valid protocol context".to_string();
        let (proof, statements) = Proof::<REPETITIONS, Language, String>::prove(
            &protocol_context,
            language_public_parameters,
            witnesses,
            rng,
        )
        .unwrap();

        let statement_values: Vec<group::Value<Language::StatementSpaceGroupElement>> = statements
            .iter()
            .map(|statement| statement.value())
            .collect();

        assert!(
            proof
                .verify_with_transcript(
                    &mut setup_partial_transcript::<REPETITIONS, Language, String>(
                        true,
                        Some(protocol_context.clone()),
                        Some(language_public_parameters.clone()),
                        Some(statement_values.clone()),
                        Some(proof.statement_masks),
                    ),
                    language_public_parameters,
                    statements.clone()
                )
                .is_ok(),
            "proofs with complete transcripts should verify"
        );

        assert!(
            matches!(
                proof
                    .verify_with_transcript(
                        &mut setup_partial_transcript::<REPETITIONS, Language, String>(
                            false,
                            Some(protocol_context.clone()),
                            Some(language_public_parameters.clone()),
                            Some(statement_values.clone()),
                            Some(proof.statement_masks),
                        ),
                        language_public_parameters,
                        statements.clone()
                    )
                    .err()
                    .unwrap(),
                Error::Proof(proof::Error::ProofVerification),
            ),
            "proofs with incomplete transcripts (missing language name) should fail"
        );

        assert!(
            matches!(
                proof
                    .verify_with_transcript(
                        &mut setup_partial_transcript::<REPETITIONS, Language, String>(
                            true,
                            None,
                            Some(language_public_parameters.clone()),
                            Some(statement_values.clone()),
                            Some(proof.statement_masks),
                        ),
                        language_public_parameters,
                        statements.clone()
                    )
                    .err()
                    .unwrap(),
                Error::Proof(proof::Error::ProofVerification),
            ),
            "proofs with incomplete transcripts (missing protocol context) should fail"
        );

        assert!(
            matches!(
                proof
                    .verify_with_transcript(
                        &mut setup_partial_transcript::<REPETITIONS, Language, String>(
                            true,
                            Some(protocol_context.clone()),
                            None,
                            Some(statement_values.clone()),
                            Some(proof.statement_masks),
                        ),
                        language_public_parameters,
                        statements.clone()
                    )
                    .err()
                    .unwrap(),
                Error::Proof(proof::Error::ProofVerification),
            ),
            "proofs with incomplete transcripts (missing public parameters) should fail"
        );

        assert!(
            matches!(
                proof
                    .verify_with_transcript(
                        &mut setup_partial_transcript::<REPETITIONS, Language, String>(
                            true,
                            Some(protocol_context.clone()),
                            Some(language_public_parameters.clone()),
                            None,
                            Some(proof.statement_masks),
                        ),
                        language_public_parameters,
                        statements.clone()
                    )
                    .err()
                    .unwrap(),
                Error::Proof(proof::Error::ProofVerification),
            ),
            "proofs with incomplete transcripts (missing statements) should fail"
        );

        assert!(
            matches!(
                proof
                    .verify_with_transcript(
                        &mut setup_partial_transcript::<REPETITIONS, Language, String>(
                            true,
                            Some(protocol_context.clone()),
                            Some(language_public_parameters.clone()),
                            Some(statement_values.clone()),
                            None,
                        ),
                        language_public_parameters,
                        statements.clone()
                    )
                    .err()
                    .unwrap(),
                Error::Proof(proof::Error::ProofVerification),
            ),
            "proofs with incomplete transcripts (missing statement masks) should fail"
        );
    }

    pub fn benchmark_proof<const REPETITIONS: usize, Language: language::Language<REPETITIONS>>(
        language_public_parameters: &Language::PublicParameters,
        extra_description: Option<String>,
        as_millis: bool,
        batch_sizes: Option<Vec<usize>>,
    ) {
        let measurement = WallTime;

        let timestamp = if as_millis { "ms" } else { "µs" };
        println!(
            "\nLanguage Name, Repetitions, Extra Description, Batch Size, Statement Computation Time ({timestamp}), Batch Normalize Time (µs), Setup Transcript Time (µs), Prove Time ({timestamp}), Verification Time ({timestamp})",
        );

        for batch_size in batch_sizes
            .unwrap_or(vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024])
            .into_iter()
        {
            let witnesses = sample_witnesses::<REPETITIONS, Language>(
                language_public_parameters,
                batch_size,
                &mut OsRng,
            );

            let now = measurement.start();
            let statements: Result<Vec<_>> = witnesses
                .iter()
                .map(|witness| Language::homomorphose(witness, language_public_parameters))
                .collect();

            let statements = statements.unwrap();
            let statements_time = measurement.end(now);

            let now = measurement.start();
            criterion::black_box(Language::StatementSpaceGroupElement::batch_normalize(
                statements.clone(),
            ));
            let normalize_time = measurement.end(now);

            let statements_values: Vec<_> = statements.iter().map(|x| x.value()).collect();

            let now = measurement.start();
            criterion::black_box(
                Proof::<REPETITIONS, Language, PhantomData<()>>::setup_transcript(
                    &PhantomData,
                    language_public_parameters,
                    statements_values.clone(),
                    // just a stub value as the value doesn't affect the benchmarking of
                    // this function
                    &[*statements_values.first().unwrap(); REPETITIONS],
                )
                .unwrap(),
            );
            let setup_transcript_time = measurement.end(now);

            let now = measurement.start();
            let (proof, _) = Proof::<REPETITIONS, Language, PhantomData<()>>::prove(
                &PhantomData,
                language_public_parameters,
                witnesses.clone(),
                &mut OsRng,
            )
            .unwrap();
            let prove_time = measurement.end(now);

            let now = measurement.start();

            proof
                .verify(&PhantomData, language_public_parameters, statements.clone())
                .unwrap();

            let verify_time = measurement.end(now);

            println!(
                "{}, {}, {}, {batch_size}, {:?}, {:?}, {:?}, {:?}, {:?}",
                Language::NAME,
                REPETITIONS,
                extra_description.clone().unwrap_or("".to_string()),
                if as_millis {
                    statements_time.as_millis()
                } else {
                    statements_time.as_micros()
                },
                normalize_time.as_micros(),
                setup_transcript_time.as_micros(),
                if as_millis {
                    prove_time.as_millis()
                } else {
                    prove_time.as_micros()
                },
                if as_millis {
                    verify_time.as_millis()
                } else {
                    verify_time.as_micros()
                },
            );
        }
    }
}
