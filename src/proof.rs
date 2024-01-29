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
    // Number of times this proof should be repeated to achieve sufficient security
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
        statement_masks: &[Language::StatementSpaceGroupElement; REPETITIONS],
        responses: &[Language::WitnessSpaceGroupElement; REPETITIONS],
    ) -> Self {
        // TODO: this is the second time, after adding to transcript, that we call `.value()` for
        // statement masks. Also, maybe get the values as parameter directly
        Self {
            statement_masks: statement_masks
                .clone()
                .map(|statement_mask| statement_mask.value()),
            responses: responses.clone().map(|response| response.value()),
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

        let mut transcript = Self::setup_transcript(
            protocol_context,
            language_public_parameters,
            statements
                .iter()
                .map(|statement| statement.value())
                .collect(),
            &statement_masks
                .clone()
                .map(|statement_mask| statement_mask.value()),
        )?;

        // TODO: maybe sample should also return the value, so no expensive conversion is necessairy
        // with `.value()`?

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
                    )
            })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| crate::Error::InternalError)?;

        Ok(Self::new(&statement_masks, &responses))
    }

    /// Verify a batched Maurer zero-knowledge proof.
    pub fn verify(
        &self,
        protocol_context: &ProtocolContext,
        language_public_parameters: &Language::PublicParameters,
        statements: Vec<Language::StatementSpaceGroupElement>,
    ) -> Result<()> {
        let batch_size = statements.len();

        // TODO: maybe here we can get statements as values already, esp. if we sample them this
        // way?
        let mut transcript = Self::setup_transcript(
            protocol_context,
            language_public_parameters,
            statements
                .iter()
                .map(|statement| statement.value())
                .collect(),
            &self.statement_masks,
        )?;

        let challenges: [Vec<ChallengeSizedNumber>; REPETITIONS] =
            Self::compute_challenges(batch_size, &mut transcript);

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

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use std::marker::PhantomData;

    use rand_core::OsRng;

    use crate::Language;
    use crate::language::tests::{generate_witness, generate_witnesses};

    use super::*;

    pub(crate) fn generate_valid_proof<const REPETITIONS: usize, Lang: Language<REPETITIONS>>(
        language_public_parameters: &Lang::PublicParameters,
        witnesses: Vec<Lang::WitnessSpaceGroupElement>,
    ) -> (
        Proof<REPETITIONS, Lang, PhantomData<()>>,
        Vec<Lang::StatementSpaceGroupElement>,
    ) {
        Proof::prove(
            &PhantomData,
            language_public_parameters,
            witnesses,
            &mut OsRng,
        )
            .unwrap()
    }

    #[allow(dead_code)]
    pub(crate) fn valid_proof_verifies<const REPETITIONS: usize, Lang: Language<REPETITIONS>>(
        language_public_parameters: Lang::PublicParameters,
        batch_size: usize,
    ) {
        let witnesses =
            generate_witnesses::<REPETITIONS, Lang>(&language_public_parameters, batch_size);

        valid_proof_verifies_internal::<REPETITIONS, Lang>(
            language_public_parameters,
            witnesses,
        )
    }

    #[allow(dead_code)]
    pub(crate) fn valid_proof_verifies_internal<
        const REPETITIONS: usize,
        Lang: Language<REPETITIONS>,
    >(
        language_public_parameters: Lang::PublicParameters,
        witnesses: Vec<Lang::WitnessSpaceGroupElement>,
    ) {
        let (proof, statements) = generate_valid_proof::<REPETITIONS, Lang>(
            &language_public_parameters,
            witnesses.clone(),
        );

        assert!(
            proof
                .verify(&PhantomData, &language_public_parameters, statements)
                .is_ok(),
            "valid proofs should verify"
        );
    }

    #[allow(dead_code)]
    pub(crate) fn invalid_proof_fails_verification<
        const REPETITIONS: usize,
        Lang: Language<REPETITIONS>,
    >(
        invalid_witness_space_value: Option<WitnessSpaceValue<REPETITIONS, Lang>>,
        invalid_statement_space_value: Option<StatementSpaceValue<REPETITIONS, Lang>>,
        language_public_parameters: Lang::PublicParameters,
        batch_size: usize,
    ) {
        let witnesses =
            generate_witnesses::<REPETITIONS, Lang>(&language_public_parameters, batch_size);

        let (valid_proof, statements) = generate_valid_proof::<REPETITIONS, Lang>(
            &language_public_parameters,
            witnesses.clone(),
        );

        let wrong_witness =
            generate_witness::<REPETITIONS, Lang>(&language_public_parameters);

        let wrong_statement =
            Lang::homomorphose(&wrong_witness, &language_public_parameters).unwrap();

        assert!(
            matches!(
                valid_proof
                    .verify(
                        &PhantomData,
                        &language_public_parameters,
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
                    .verify(
                        &PhantomData,
                        &language_public_parameters,
                        statements.clone(),
                    )
                    .err()
                    .unwrap(),
                Error::Proof(proof::Error::ProofVerification)
            ),
            "proof with a wrong response shouldn't verify"
        );

        let mut invalid_proof = valid_proof.clone();
        invalid_proof.statement_masks = [wrong_statement.neutral().value(); REPETITIONS];

        assert!(
            matches!(
                invalid_proof
                    .verify(
                        &PhantomData,
                        &language_public_parameters,
                        statements.clone(),
                    )
                    .err()
                    .unwrap(),
                Error::Proof(proof::Error::ProofVerification)
            ),
            "proof with a neutral statement_mask shouldn't verify"
        );

        let mut invalid_proof = valid_proof.clone();
        invalid_proof.responses = [wrong_witness.neutral().value(); REPETITIONS];

        assert!(
            matches!(
                invalid_proof
                    .verify(
                        &PhantomData,
                        &language_public_parameters,
                        statements.clone(),
                    )
                    .err()
                    .unwrap(),
                Error::Proof(proof::Error::ProofVerification)
            ),
            "proof with a neutral response shouldn't verify"
        );

        if let Some(invalid_statement_space_value) = invalid_statement_space_value {
            let mut invalid_proof = valid_proof.clone();
            invalid_proof.statement_masks = [invalid_statement_space_value; REPETITIONS];

            assert!(matches!(
            invalid_proof
                .verify(
                    &PhantomData,
                    &language_public_parameters,
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
                    &language_public_parameters,
                    statements.clone(),
                )
                .err()
                .unwrap(),
            Error::GroupInstantiation(group::Error::InvalidGroupElement)),
                    "proof with an invalid response value should generate an invalid parameter error when checking the element is not in the group"
            );
        }
    }

    #[allow(dead_code)]
    pub(crate) fn proof_over_invalid_public_parameters_fails_verification<
        const REPETITIONS: usize,
        Lang: Language<REPETITIONS>,
    >(
        prover_language_public_parameters: Lang::PublicParameters,
        verifier_language_public_parameters: Lang::PublicParameters,
        witnesses: Vec<Lang::WitnessSpaceGroupElement>,
    ) {
        let (proof, statements) = generate_valid_proof::<REPETITIONS, Lang>(
            &prover_language_public_parameters,
            witnesses.clone(),
        );

        assert!(
            matches!(
                proof
                    .verify(
                        &PhantomData,
                        &verifier_language_public_parameters,
                        statements,
                    )
                    .err()
                    .unwrap(),
                Error::Proof(proof::Error::ProofVerification)
            ),
            "proof over wrong public parameters shouldn't verify"
        );
    }
}