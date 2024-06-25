// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use std::{marker::PhantomData, ops::Mul};

use commitment::{pedersen, pedersen::Pedersen, HomomorphicCommitmentScheme};
use group::{self_product, KnownOrderGroupElement, Samplable};
use serde::{Deserialize, Serialize};

use crate::{language::GroupsPublicParameters, Result, SOUND_PROOFS_REPETITIONS};

/// Ratio Between Committed Values is the Discrete Log Maurer Language.
/// $$ (m,r_1,r_2) \mapsto Com_{G,H}(m; r_1), Com_{X,H}(m, r_2) $$
/// Where $X=g^x$ is a public parameter, and we use Pedersen commitments where
/// $Com_{X,H}(m,r_2) = Com_{G,H}(x*m, r_2)$.
///
/// SECURITY NOTICE:
/// Because correctness and zero-knowledge is guaranteed for any group in this language, we choose
/// to provide a fully generic implementation.
///
/// However, knowledge-soundness proofs are group-dependent, and thus we can only assure security
/// for groups for which we know how to prove it.
///
/// In the paper, we have proved it for any prime known-order group; so it is safe to use with a
/// `PrimeOrderGroupElement`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
pub struct Language<const SCALAR_LIMBS: usize, Scalar, GroupElement> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
}

impl<const SCALAR_LIMBS: usize, Scalar, GroupElement> crate::Language<SOUND_PROOFS_REPETITIONS>
    for Language<SCALAR_LIMBS, Scalar, GroupElement>
where
    Scalar: KnownOrderGroupElement<SCALAR_LIMBS>
        + Samplable
        + Mul<GroupElement, Output = GroupElement>
        + for<'r> Mul<&'r GroupElement, Output = GroupElement>
        + Copy,
    GroupElement: group::GroupElement,
{
    type WitnessSpaceGroupElement = self_product::GroupElement<3, Scalar>;
    type StatementSpaceGroupElement = self_product::GroupElement<2, GroupElement>;

    type PublicParameters = PublicParameters<
        Scalar::PublicParameters,
        GroupElement::PublicParameters,
        GroupElement::Value,
    >;
    const NAME: &'static str = "Ratio Between Committed Values is the Discrete Log";

    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> Result<Self::StatementSpaceGroupElement> {
        let commitment_scheme =
            Pedersen::new(&language_public_parameters.commitment_scheme_public_parameters)?;

        // The paper specifies a trick to transform this langauge into a homomorphism:
        // Use $g^x$ as the base for the message of the second commitment, and then the commitment
        // on $m*x$ becomes the commitment on $m$, with the discrete log $x$ now appearing
        // in the message base of the second commitment.
        let altered_base_commitment_scheme = Pedersen::new(
            &language_public_parameters
                .commitment_scheme_public_parameters
                .with_altered_message_generators([language_public_parameters.base_by_discrete_log]),
        )?;

        Ok([
            commitment_scheme.commit(
                &[*witness.commitment_message()].into(),
                witness.first_commitment_randomness(),
            ),
            altered_base_commitment_scheme.commit(
                &[*witness.commitment_message()].into(),
                witness.second_commitment_randomness(),
            ),
        ]
        .into())
    }
}

pub trait WitnessAccessors<Scalar: group::GroupElement> {
    fn commitment_message(&self) -> &Scalar;

    fn first_commitment_randomness(&self) -> &Scalar;

    fn second_commitment_randomness(&self) -> &Scalar;
}

impl<Scalar: group::GroupElement> WitnessAccessors<Scalar>
    for self_product::GroupElement<3, Scalar>
{
    fn commitment_message(&self) -> &Scalar {
        let value: &[Scalar; 3] = self.into();

        &value[0]
    }

    fn first_commitment_randomness(&self) -> &Scalar {
        let value: &[Scalar; 3] = self.into();

        &value[1]
    }

    fn second_commitment_randomness(&self) -> &Scalar {
        let value: &[Scalar; 3] = self.into();

        &value[2]
    }
}

pub trait StatementAccessors<GroupElement: group::GroupElement> {
    fn committment_of_discrete_log(&self) -> &GroupElement;

    fn altered_base_committment_of_discrete_log(&self) -> &GroupElement;
}

impl<GroupElement: group::GroupElement> StatementAccessors<GroupElement>
    for self_product::GroupElement<2, GroupElement>
{
    fn committment_of_discrete_log(&self) -> &GroupElement {
        let value: &[_; 2] = self.into();

        &value[0]
    }

    fn altered_base_committment_of_discrete_log(&self) -> &GroupElement {
        let value: &[_; 2] = self.into();

        &value[1]
    }
}

/// The Public Parameters of the Ratio Between Committed Values is the Discrete Log Maurer
/// Language.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PublicParameters<ScalarPublicParameters, GroupPublicParameters, GroupElementValue> {
    pub groups_public_parameters: GroupsPublicParameters<
        self_product::PublicParameters<3, ScalarPublicParameters>,
        self_product::PublicParameters<2, GroupPublicParameters>,
    >,
    pub commitment_scheme_public_parameters: pedersen::PublicParameters<
        1,
        GroupElementValue,
        ScalarPublicParameters,
        GroupPublicParameters,
    >,
    // The base $g$ by the discrete log (witness $x$) $g^x$ used as the public key in the paper.
    pub base_by_discrete_log: GroupElementValue,
}

impl<ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
    PublicParameters<ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
{
    pub fn new<const SCALAR_LIMBS: usize, Scalar, GroupElement>(
        scalar_group_public_parameters: Scalar::PublicParameters,
        group_public_parameters: GroupElement::PublicParameters,
        commitment_scheme_public_parameters: commitment::PublicParameters<
            SCALAR_LIMBS,
            Pedersen<1, SCALAR_LIMBS, Scalar, GroupElement>,
        >,
        base_by_discrete_log: GroupElement,
    ) -> Self
    where
        Scalar: group::GroupElement<PublicParameters = ScalarPublicParameters>
            + KnownOrderGroupElement<SCALAR_LIMBS>
            + Samplable
            + Mul<GroupElement, Output = GroupElement>
            + for<'r> Mul<&'r GroupElement, Output = GroupElement>
            + Copy,
        GroupElement: group::GroupElement<
            Value = GroupElementValue,
            PublicParameters = GroupPublicParameters,
        >,
    {
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: group::PublicParameters::<
                    self_product::GroupElement<3, Scalar>,
                >::new(
                    scalar_group_public_parameters
                ),
                statement_space_public_parameters: group::PublicParameters::<
                    self_product::GroupElement<2, GroupElement>,
                >::new(group_public_parameters),
            },
            commitment_scheme_public_parameters,
            base_by_discrete_log: base_by_discrete_log.value(),
        }
    }
}

impl<ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
    AsRef<
        GroupsPublicParameters<
            self_product::PublicParameters<3, ScalarPublicParameters>,
            self_product::PublicParameters<2, GroupPublicParameters>,
        >,
    > for PublicParameters<ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
{
    fn as_ref(
        &self,
    ) -> &GroupsPublicParameters<
        self_product::PublicParameters<3, ScalarPublicParameters>,
        self_product::PublicParameters<2, GroupPublicParameters>,
    > {
        &self.groups_public_parameters
    }
}

#[cfg(any(test, feature = "benchmarking"))]
#[allow(unused_imports)]
mod tests {
    use crypto_bigint::U256;
    use group::{secp256k1, GroupElement};
    use rand_core::OsRng;
    use rstest::rstest;

    use crate::{language, test_helpers};

    use super::*;

    pub(crate) type Lang =
        Language<{ secp256k1::SCALAR_LIMBS }, secp256k1::Scalar, secp256k1::GroupElement>;

    pub(crate) fn language_public_parameters(
    ) -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        let generator = secp256k1::GroupElement::new(
            secp256k1_group_public_parameters.generator,
            &secp256k1_group_public_parameters,
        )
        .unwrap();

        let discrete_log =
            secp256k1::Scalar::sample(&secp256k1_scalar_public_parameters, &mut OsRng).unwrap();

        let base_by_discrete_log = discrete_log * generator;

        let pedersen_public_parameters = pedersen::PublicParameters::derive_default::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::GroupElement,
        >()
        .unwrap();

        PublicParameters::new::<
            { secp256k1::SCALAR_LIMBS },
            secp256k1::Scalar,
            secp256k1::GroupElement,
        >(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
            pedersen_public_parameters,
            base_by_discrete_log,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

        test_helpers::valid_proof_verifies::<SOUND_PROOFS_REPETITIONS, Lang>(
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
        let language_public_parameters = language_public_parameters();

        // No invalid values as secp256k1 statically defines a group,
        // `k256::AffinePoint` assures deserialized values are on a curve,
        // and `Value` can only be instantiated through deserialization
        test_helpers::invalid_proof_fails_verification::<SOUND_PROOFS_REPETITIONS, Lang>(
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
        let verifier_public_parameters = language_public_parameters();
        let mut prover_public_parameters = verifier_public_parameters.clone();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();
        prover_public_parameters.base_by_discrete_log = secp256k1::GroupElement::new(
            prover_public_parameters.base_by_discrete_log,
            &secp256k1_group_public_parameters,
        )
        .unwrap()
        .neutral()
        .value();

        test_helpers::proof_over_invalid_public_parameters_fails_verification::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
        >(
            &prover_public_parameters,
            &verifier_public_parameters,
            batch_size,
            &mut OsRng,
        );

        let mut prover_public_parameters = verifier_public_parameters.clone();
        prover_public_parameters
            .groups_public_parameters
            .statement_space_public_parameters
            .public_parameters
            .curve_equation_a = U256::from(42u8);

        test_helpers::proof_over_invalid_public_parameters_fails_verification::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
        >(
            &prover_public_parameters,
            &verifier_public_parameters,
            batch_size,
            &mut OsRng,
        );

        let mut prover_public_parameters = verifier_public_parameters.clone();
        prover_public_parameters
            .commitment_scheme_public_parameters
            .message_generators[0] = prover_public_parameters
            .commitment_scheme_public_parameters
            .randomness_generator;

        test_helpers::proof_over_invalid_public_parameters_fails_verification::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
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
        let language_public_parameters = language_public_parameters();

        test_helpers::proof_with_incomplete_transcript_fails::<SOUND_PROOFS_REPETITIONS, Lang>(
            &language_public_parameters,
            batch_size,
            &mut OsRng,
        )
    }

    #[rstest]
    #[case(1, 1)]
    #[case(1, 2)]
    #[case(2, 1)]
    #[case(2, 3)]
    #[case(5, 2)]
    fn aggregates(#[case] number_of_parties: usize, #[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

        test_helpers::aggregates::<SOUND_PROOFS_REPETITIONS, Lang>(
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
        let language_public_parameters = language_public_parameters();

        test_helpers::unresponsive_parties_aborts_session_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
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
        let language_public_parameters = language_public_parameters();

        test_helpers::wrong_decommitment_aborts_session_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
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
        let language_public_parameters = language_public_parameters();

        test_helpers::failed_proof_share_verification_aborts_session_identifiably::<
            SOUND_PROOFS_REPETITIONS,
            Lang,
        >(&language_public_parameters, number_of_parties, batch_size);
    }
}

#[cfg(feature = "benchmarking")]
pub mod benches {
    use criterion::Criterion;

    use crate::{
        discrete_log_ratio_of_committed_values::tests::{language_public_parameters, Lang},
        test_helpers,
    };

    use super::*;

    pub(crate) fn benchmark(_c: &mut Criterion) {
        let language_public_parameters = language_public_parameters();

        test_helpers::benchmark_proof::<SOUND_PROOFS_REPETITIONS, Lang>(
            &language_public_parameters,
            None,
            false,
            None,
        );
        test_helpers::benchmark_aggregation::<SOUND_PROOFS_REPETITIONS, Lang>(
            &language_public_parameters,
            None,
            false,
            None,
        );
    }
}
