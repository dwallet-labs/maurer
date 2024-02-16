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
            group::GroupElement<PublicParameters = MessageSpacePublicParameters>,
        CommitmentScheme::RandomnessSpaceGroupElement:
            group::GroupElement<PublicParameters = RandomnessSpacePublicParameters>,
        CommitmentScheme::CommitmentSpaceGroupElement:
            group::GroupElement<PublicParameters = CommitmentSpacePublicParameters>,
        CommitmentScheme: HomomorphicCommitmentScheme<
            MESSAGE_SPACE_SCALAR_LIMBS,
            PublicParameters = CommitmentSchemePublicParameters,
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

#[cfg(any(test, feature = "benchmarking"))]
#[allow(unused_imports)]
mod tests {
    use commitment::pedersen;
    use commitment::pedersen::Pedersen;
    use group::secp256k1;
    use rand_core::OsRng;
    use rstest::rstest;

    use crate::{
        language, test_helpers, BIT_SOUNDNESS_PROOFS_REPETITIONS, SOUND_PROOFS_REPETITIONS,
    };

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

    pub(crate) fn language_public_parameters<const REPETITIONS: usize, const BATCH_SIZE: usize>(
    ) -> language::PublicParameters<REPETITIONS, Lang<REPETITIONS, BATCH_SIZE>> {
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
            pedersen::PublicParameters::derive_default::<
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

        test_helpers::valid_proof_verifies::<
            SOUND_PROOFS_REPETITIONS,
            Lang<SOUND_PROOFS_REPETITIONS, 1>,
        >(&language_public_parameters, batch_size, &mut OsRng);

        test_helpers::valid_proof_verifies::<
            BIT_SOUNDNESS_PROOFS_REPETITIONS,
            Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 1>,
        >(&language_public_parameters, batch_size, &mut OsRng)
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn invalid_proof_fails_verification(#[case] batch_size: usize) {
        let language_public_parameters =
            language_public_parameters::<SOUND_PROOFS_REPETITIONS, 1>();

        // No invalid values as secp256k1 statically defines group,
        // `k256::AffinePoint` assures deserialized values are on curve,
        // and `Value` can only be instantiated through deserialization
        test_helpers::invalid_proof_fails_verification::<
            SOUND_PROOFS_REPETITIONS,
            Lang<SOUND_PROOFS_REPETITIONS, 1>,
        >(
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
        let verifier_public_parameters =
            language_public_parameters::<SOUND_PROOFS_REPETITIONS, 1>();
        let mut prover_public_parameters = verifier_public_parameters.clone();

        prover_public_parameters
            .commitment_scheme_public_parameters
            .message_generators[0] = prover_public_parameters
            .commitment_scheme_public_parameters
            .randomness_generator;

        test_helpers::proof_over_invalid_public_parameters_fails_verification::<
            SOUND_PROOFS_REPETITIONS,
            Lang<SOUND_PROOFS_REPETITIONS, 1>,
        >(
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
        let language_public_parameters =
            language_public_parameters::<SOUND_PROOFS_REPETITIONS, 1>();

        test_helpers::proof_with_incomplete_transcript_fails::<
            SOUND_PROOFS_REPETITIONS,
            Lang<SOUND_PROOFS_REPETITIONS, 1>,
        >(&language_public_parameters, batch_size, &mut OsRng)
    }

    #[rstest]
    #[case(1, 1)]
    #[case(1, 2)]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(5, 2)]
    fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
        let language_public_parameters =
            language_public_parameters::<SOUND_PROOFS_REPETITIONS, 1>();

        test_helpers::aggregates::<SOUND_PROOFS_REPETITIONS, Lang<SOUND_PROOFS_REPETITIONS, 1>>(
            &language_public_parameters,
            number_of_parties,
            batch_size,
        );
    }

    #[rstest]
    #[case(2, 1)]
    #[case(3, 1)]
    #[case(5, 2)]
    fn unresponsive_parties_aborts_session_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters =
            language_public_parameters::<SOUND_PROOFS_REPETITIONS, 1>();

        test_helpers::unresponsive_parties_aborts_session_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            Lang<SOUND_PROOFS_REPETITIONS, 1>,
        >(&language_public_parameters, number_of_parties, batch_size);
    }

    #[rstest]
    #[case(2, 1)]
    #[case(3, 1)]
    #[case(5, 2)]
    fn wrong_decommitment_aborts_session_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters =
            language_public_parameters::<SOUND_PROOFS_REPETITIONS, 1>();

        test_helpers::wrong_decommitment_aborts_session_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            Lang<SOUND_PROOFS_REPETITIONS, 1>,
        >(&language_public_parameters, number_of_parties, batch_size);
    }

    #[rstest]
    #[case(2, 1)]
    #[case(3, 1)]
    #[case(5, 2)]
    fn failed_proof_share_verification_aborts_session_identifiably(
        #[case] number_of_parties: usize,
        #[case] batch_size: usize,
    ) {
        let language_public_parameters =
            language_public_parameters::<SOUND_PROOFS_REPETITIONS, 1>();

        test_helpers::failed_proof_share_verification_aborts_session_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            Lang<SOUND_PROOFS_REPETITIONS, 1>,
        >(&language_public_parameters, number_of_parties, batch_size);
    }
}

#[cfg(feature = "benchmarking")]
pub(crate) mod benches {
    use crate::knowledge_of_decommitment::tests::{language_public_parameters, Lang};
    use crate::test_helpers;
    use crate::{BIT_SOUNDNESS_PROOFS_REPETITIONS, SOUND_PROOFS_REPETITIONS};
    use criterion::Criterion;

    pub(crate) fn benchmark(_c: &mut Criterion) {
        let sound_language_public_parameters =
            language_public_parameters::<SOUND_PROOFS_REPETITIONS, 1>();

        test_helpers::benchmark_proof::<SOUND_PROOFS_REPETITIONS, Lang<SOUND_PROOFS_REPETITIONS, 1>>(
            &sound_language_public_parameters,
            None,
            false,
            None,
        );
        test_helpers::benchmark_aggregation::<
            SOUND_PROOFS_REPETITIONS,
            Lang<SOUND_PROOFS_REPETITIONS, 1>,
        >(&sound_language_public_parameters, None, false, None);

        let language_public_parameters1 =
            language_public_parameters::<BIT_SOUNDNESS_PROOFS_REPETITIONS, 1>();
        let language_public_parameters2 =
            language_public_parameters::<BIT_SOUNDNESS_PROOFS_REPETITIONS, 2>();
        let language_public_parameters4 =
            language_public_parameters::<BIT_SOUNDNESS_PROOFS_REPETITIONS, 4>();
        let language_public_parameters8 =
            language_public_parameters::<BIT_SOUNDNESS_PROOFS_REPETITIONS, 8>();
        let language_public_parameters16 =
            language_public_parameters::<BIT_SOUNDNESS_PROOFS_REPETITIONS, 16>();
        let language_public_parameters32 =
            language_public_parameters::<BIT_SOUNDNESS_PROOFS_REPETITIONS, 32>();
        let language_public_parameters64 =
            language_public_parameters::<BIT_SOUNDNESS_PROOFS_REPETITIONS, 64>();
        let language_public_parameters128 =
            language_public_parameters::<BIT_SOUNDNESS_PROOFS_REPETITIONS, 128>();

        test_helpers::benchmark_proof::<
            BIT_SOUNDNESS_PROOFS_REPETITIONS,
            Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 1>,
        >(
            &language_public_parameters1,
            Some("1".to_string()),
            true,
            Some(vec![
                1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192,
            ]),
        );
        test_helpers::benchmark_proof::<
            BIT_SOUNDNESS_PROOFS_REPETITIONS,
            Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 2>,
        >(
            &language_public_parameters2,
            Some("2".to_string()),
            true,
            Some(vec![
                1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192,
            ]),
        );
        test_helpers::benchmark_proof::<
            BIT_SOUNDNESS_PROOFS_REPETITIONS,
            Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 4>,
        >(
            &language_public_parameters4,
            Some("4".to_string()),
            true,
            Some(vec![
                1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192,
            ]),
        );
        test_helpers::benchmark_proof::<
            BIT_SOUNDNESS_PROOFS_REPETITIONS,
            Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 8>,
        >(
            &language_public_parameters8,
            Some("8".to_string()),
            true,
            Some(vec![
                1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192,
            ]),
        );
        test_helpers::benchmark_proof::<
            BIT_SOUNDNESS_PROOFS_REPETITIONS,
            Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 16>,
        >(
            &language_public_parameters16,
            Some("16".to_string()),
            true,
            Some(vec![
                1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192,
            ]),
        );
        test_helpers::benchmark_proof::<
            BIT_SOUNDNESS_PROOFS_REPETITIONS,
            Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 32>,
        >(
            &language_public_parameters32,
            Some("32".to_string()),
            true,
            Some(vec![
                1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192,
            ]),
        );
        test_helpers::benchmark_proof::<
            BIT_SOUNDNESS_PROOFS_REPETITIONS,
            Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 64>,
        >(
            &language_public_parameters64,
            Some("64".to_string()),
            true,
            Some(vec![
                1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192,
            ]),
        );
        test_helpers::benchmark_proof::<
            BIT_SOUNDNESS_PROOFS_REPETITIONS,
            Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 128>,
        >(
            &language_public_parameters128,
            Some("128".to_string()),
            true,
            Some(vec![
                1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192,
            ]),
        );

        test_helpers::benchmark_aggregation::<
            BIT_SOUNDNESS_PROOFS_REPETITIONS,
            Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 1>,
        >(
            &language_public_parameters1,
            Some("1".to_string()),
            true,
            Some(vec![1, 2, 4, 8, 16, 32, 64]),
        );
        test_helpers::benchmark_aggregation::<
            BIT_SOUNDNESS_PROOFS_REPETITIONS,
            Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 2>,
        >(
            &language_public_parameters2,
            Some("2".to_string()),
            true,
            Some(vec![1, 2, 4, 8, 16, 32, 64]),
        );
        test_helpers::benchmark_aggregation::<
            BIT_SOUNDNESS_PROOFS_REPETITIONS,
            Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 4>,
        >(
            &language_public_parameters4,
            Some("4".to_string()),
            true,
            Some(vec![1, 2, 4, 8, 16, 32, 64]),
        );
        test_helpers::benchmark_aggregation::<
            BIT_SOUNDNESS_PROOFS_REPETITIONS,
            Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 8>,
        >(
            &language_public_parameters8,
            Some("8".to_string()),
            true,
            Some(vec![1, 2, 4, 8, 16, 32, 64]),
        );
        test_helpers::benchmark_aggregation::<
            BIT_SOUNDNESS_PROOFS_REPETITIONS,
            Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 16>,
        >(
            &language_public_parameters16,
            Some("16".to_string()),
            true,
            Some(vec![1, 2, 4, 8, 16, 32, 64]),
        );
        test_helpers::benchmark_aggregation::<
            BIT_SOUNDNESS_PROOFS_REPETITIONS,
            Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 32>,
        >(
            &language_public_parameters32,
            Some("32".to_string()),
            true,
            Some(vec![1, 2, 4, 8, 16, 32, 64]),
        );

        test_helpers::benchmark_aggregation::<
            BIT_SOUNDNESS_PROOFS_REPETITIONS,
            Lang<BIT_SOUNDNESS_PROOFS_REPETITIONS, 64>,
        >(
            &language_public_parameters64,
            Some("64".to_string()),
            true,
            Some(vec![1, 2, 4, 8, 16, 32, 64]),
        );
    }
}
