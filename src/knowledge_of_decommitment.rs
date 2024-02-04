// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use std::marker::PhantomData;

use commitment::{GroupsPublicParametersAccessors, HomomorphicCommitmentScheme};
use group::{direct_product, Samplable};
use serde::{Deserialize, Serialize};

use crate::language::GroupsPublicParameters;
use crate::Result;

/// Knowledge of Decommitment Maurer Language.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
pub struct Language<
    const REPETITIONS: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    CommitmentScheme: HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>,
> {
    _commitment_choice: PhantomData<CommitmentScheme>,
}

impl<
    const REPETITIONS: usize,
    const MESSAGE_SPACE_SCALAR_LIMBS: usize,
    CommitmentScheme: HomomorphicCommitmentScheme<MESSAGE_SPACE_SCALAR_LIMBS>,
> crate::Language<REPETITIONS>
for Language<REPETITIONS, MESSAGE_SPACE_SCALAR_LIMBS, CommitmentScheme>
    where
        CommitmentScheme::MessageSpaceGroupElement: Samplable,
        CommitmentScheme::RandomnessSpaceGroupElement: Samplable,
{
    type WitnessSpaceGroupElement = direct_product::GroupElement<
        CommitmentScheme::MessageSpaceGroupElement,
        CommitmentScheme::RandomnessSpaceGroupElement,
    >;
    type StatementSpaceGroupElement = CommitmentScheme::CommitmentSpaceGroupElement;

    type PublicParameters = PublicParameters<
        group::PublicParameters<CommitmentScheme::MessageSpaceGroupElement>,
        group::PublicParameters<CommitmentScheme::RandomnessSpaceGroupElement>,
        group::PublicParameters<CommitmentScheme::CommitmentSpaceGroupElement>,
        CommitmentScheme::PublicParameters,
    >;

    const NAME: &'static str = "Knowledge of Decommitment";

    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> Result<Self::StatementSpaceGroupElement> {
        let commitment_scheme =
            CommitmentScheme::new(&language_public_parameters.commitment_scheme_public_parameters)?;

        Ok(commitment_scheme.commit(
            witness.commitment_message(),
            witness.commitment_randomness(),
        ))
    }
}

pub trait WitnessAccessors<
    CommitmentSchemeMessageSpaceGroupElement,
    CommitmentSchemeRandomnessSpaceGroupElement,
>
{
    fn commitment_message(&self) -> &CommitmentSchemeMessageSpaceGroupElement;

    fn commitment_randomness(&self) -> &CommitmentSchemeRandomnessSpaceGroupElement;
}

impl<CommitmentSchemeMessageSpaceGroupElement, CommitmentSchemeRandomnessSpaceGroupElement>
WitnessAccessors<
    CommitmentSchemeMessageSpaceGroupElement,
    CommitmentSchemeRandomnessSpaceGroupElement,
>
for direct_product::GroupElement<
    CommitmentSchemeMessageSpaceGroupElement,
    CommitmentSchemeRandomnessSpaceGroupElement,
>
{
    fn commitment_message(&self) -> &CommitmentSchemeMessageSpaceGroupElement {
        let value: (&_, &_) = self.into();

        value.0
    }

    fn commitment_randomness(&self) -> &CommitmentSchemeRandomnessSpaceGroupElement {
        let value: (&_, &_) = self.into();

        value.1
    }
}

/// The Public Parameters of the Knowledge of Decommitment Maurer Language.
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<
    MessageSpacePublicParameters,
    RandomnessSpacePublicParameters,
    CommitmentSpacePublicParameters,
    CommitmentSchemePublicParameters,
> {
    pub groups_public_parameters: GroupsPublicParameters<
        direct_product::PublicParameters<
            MessageSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        CommitmentSpacePublicParameters,
    >,
    pub commitment_scheme_public_parameters: CommitmentSchemePublicParameters,
}

impl<
    MessageSpacePublicParameters: Clone,
    RandomnessSpacePublicParameters: Clone,
    CommitmentSpacePublicParameters: Clone,
    CommitmentSchemePublicParameters,
>
PublicParameters<
    MessageSpacePublicParameters,
    RandomnessSpacePublicParameters,
    CommitmentSpacePublicParameters,
    CommitmentSchemePublicParameters,
>
{
    pub fn new<
        const REPETITIONS: usize,
        const MESSAGE_SPACE_SCALAR_LIMBS: usize,
        CommitmentScheme,
    >(
        commitment_scheme_public_parameters: CommitmentScheme::PublicParameters,
    ) -> Self
        where
            CommitmentScheme::MessageSpaceGroupElement:
            group::GroupElement<PublicParameters=MessageSpacePublicParameters>,
            CommitmentScheme::RandomnessSpaceGroupElement:
            group::GroupElement<PublicParameters=RandomnessSpacePublicParameters>,
            CommitmentScheme::CommitmentSpaceGroupElement:
            group::GroupElement<PublicParameters=CommitmentSpacePublicParameters>,
            CommitmentScheme: HomomorphicCommitmentScheme<
                MESSAGE_SPACE_SCALAR_LIMBS,
                PublicParameters=CommitmentSchemePublicParameters,
            >,
            CommitmentSchemePublicParameters: AsRef<
                commitment::GroupsPublicParameters<
                    MessageSpacePublicParameters,
                    RandomnessSpacePublicParameters,
                    CommitmentSpacePublicParameters,
                >,
            >,
    {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: direct_product::PublicParameters(
                    commitment_scheme_public_parameters
                        .message_space_public_parameters()
                        .clone(),
                    commitment_scheme_public_parameters
                        .randomness_space_public_parameters()
                        .clone(),
                ),
                statement_space_public_parameters: commitment_scheme_public_parameters
                    .commitment_space_public_parameters()
                    .clone(),
            },
            commitment_scheme_public_parameters,
        }
    }
}

impl<
    MessageSpacePublicParameters,
    RandomnessSpacePublicParameters,
    CommitmentSpacePublicParameters,
    CommitmentSchemePublicParameters,
>
AsRef<
    GroupsPublicParameters<
        direct_product::PublicParameters<
            MessageSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        CommitmentSpacePublicParameters,
    >,
>
for PublicParameters<
    MessageSpacePublicParameters,
    RandomnessSpacePublicParameters,
    CommitmentSpacePublicParameters,
    CommitmentSchemePublicParameters,
>
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        direct_product::PublicParameters<
            MessageSpacePublicParameters,
            RandomnessSpacePublicParameters,
        >,
        CommitmentSpacePublicParameters,
    > {
        &self.groups_public_parameters
    }
}

#[cfg(feature = "test_helpers")]
mod tests {
    use commitment::pedersen;
    use commitment::pedersen::Pedersen;
    use group::secp256k1;
    use rand_core::OsRng;
    use rstest::rstest;

    use crate::{BIT_SOUNDNESS_PROOFS_REPETITIONS, language, SOUND_PROOFS_REPETITIONS, test_helpers};

    use super::*;

    pub(crate) type Lang<const REPETITIONS: usize, const BATCH_SIZE: usize> = Language<
        REPETITIONS,
        { secp256k1::SCALAR_LIMBS },
        Pedersen<
            BATCH_SIZE,
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >,
    >;

    pub(crate) fn language_public_parameters<
        const REPETITIONS: usize,
        const BATCH_SIZE: usize,
    >() -> language::PublicParameters<REPETITIONS, Lang<REPETITIONS, BATCH_SIZE>> {
        PublicParameters::new::<
            REPETITIONS,
            { secp256k1::SCALAR_LIMBS },
            Pedersen<
                BATCH_SIZE,
                { secp256k1::SCALAR_LIMBS },
                secp256k1::Scalar,
                secp256k1::GroupElement,
            >,
        >(
            pedersen::PublicParameters::default::<
                { secp256k1::SCALAR_LIMBS },
                secp256k1::GroupElement,
            >()
                .unwrap(),
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters::<1, 1>();

        test_helpers::valid_proof_verifies::<SOUND_PROOFS_REPETITIONS, Lang<SOUND_PROOFS_REPETITIONS, 1>>(
            &language_public_parameters,
            batch_size,
            &mut OsRng,
        );

        test_helpers::valid_proof_verifies::<BIT_SOUNDNESS_PROOFS_REPETITIONS, Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 1>>(
            &language_public_parameters,
            batch_size,
            &mut OsRng,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn invalid_proof_fails_verification(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters::<SOUND_PROOFS_REPETITIONS, 1>();

        // No invalid values as secp256k1 statically defines group,
        // `k256::AffinePoint` assures deserialized values are on curve,
        // and `Value` can only be instantiated through deserialization
        test_helpers::invalid_proof_fails_verification::<SOUND_PROOFS_REPETITIONS, Lang<SOUND_PROOFS_REPETITIONS, 1>>(
            None,
            None,
            &language_public_parameters,
            batch_size,
            &mut OsRng,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn proof_over_invalid_public_parameters_fails_verification(#[case] batch_size: usize) {
        let verifier_public_parameters = language_public_parameters::<SOUND_PROOFS_REPETITIONS, 1>();
        let mut prover_public_parameters = verifier_public_parameters.clone();

        prover_public_parameters.commitment_scheme_public_parameters.message_generators[0] = prover_public_parameters.commitment_scheme_public_parameters.randomness_generator;

        test_helpers::proof_over_invalid_public_parameters_fails_verification::<SOUND_PROOFS_REPETITIONS, Lang<SOUND_PROOFS_REPETITIONS, 1>>(
            &prover_public_parameters,
            &verifier_public_parameters,
            batch_size,
            &mut OsRng,
        );
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn proof_with_incomplete_transcript_fails(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters::<SOUND_PROOFS_REPETITIONS, 1>();

        test_helpers::proof_with_incomplete_transcript_fails::<SOUND_PROOFS_REPETITIONS, Lang<SOUND_PROOFS_REPETITIONS, 1>>(
            &language_public_parameters,
            batch_size,
            &mut OsRng,
        )
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use criterion::Criterion;
    use crate::test_helpers;
    use crate::knowledge_of_decommitment::tests::{Lang, language_public_parameters};
    use crate::{BIT_SOUNDNESS_PROOFS_REPETITIONS, SOUND_PROOFS_REPETITIONS};

    pub(crate) fn benchmark(_c: &mut Criterion) {
        // let language_public_parameters = language_public_parameters::<SOUND_PROOFS_REPETITIONS, 1>();
        //
        // test_helpers::benchmark_proof::<SOUND_PROOFS_REPETITIONS, Lang<SOUND_PROOFS_REPETITIONS, 1>>(&language_public_parameters, None, false);
        // test_helpers::benchmark_aggregation::<SOUND_PROOFS_REPETITIONS, Lang<SOUND_PROOFS_REPETITIONS, 1>>(&language_public_parameters, None, false);

        let language_public_parameters = crate::knowledge_of_decommitment::tests::language_public_parameters::<BIT_SOUNDNESS_PROOFS_REPETITIONS, 1>();

        test_helpers::benchmark_proof::<BIT_SOUNDNESS_PROOFS_REPETITIONS, Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 1>>(&language_public_parameters, Some("1".to_string()), true);
        test_helpers::benchmark_aggregation::<BIT_SOUNDNESS_PROOFS_REPETITIONS, Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 1>>(&language_public_parameters, Some("1".to_string()), true);

        let language_public_parameters = crate::knowledge_of_decommitment::tests::language_public_parameters::<BIT_SOUNDNESS_PROOFS_REPETITIONS, 10>();

        test_helpers::benchmark_proof::<BIT_SOUNDNESS_PROOFS_REPETITIONS, Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 10>>(&language_public_parameters, Some("10".to_string()), true);
        test_helpers::benchmark_aggregation::<BIT_SOUNDNESS_PROOFS_REPETITIONS, Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 10>>(&language_public_parameters, Some("10".to_string()), true);

        let language_public_parameters = crate::knowledge_of_decommitment::tests::language_public_parameters::<BIT_SOUNDNESS_PROOFS_REPETITIONS, 100>();

        test_helpers::benchmark_proof::<BIT_SOUNDNESS_PROOFS_REPETITIONS, Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 100>>(&language_public_parameters, Some("100".to_string()), true);
        test_helpers::benchmark_aggregation::<BIT_SOUNDNESS_PROOFS_REPETITIONS, Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 100>>(&language_public_parameters, Some("100".to_string()), true);
    }
}