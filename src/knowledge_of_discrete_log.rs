// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use std::{marker::PhantomData, ops::Mul};

use group::{CyclicGroupElement, Samplable};
use serde::{Deserialize, Serialize};

#[cfg(feature = "benchmarking")]
pub(crate) use benches::benchmark;

use crate::language::GroupsPublicParameters;
use crate::Result;
use crate::SOUND_PROOFS_REPETITIONS;

/// Knowledge of Discrete Log Maurer Language.
///
/// SECURITY NOTICE:
/// Because correctness and zero-knowledge is guaranteed for any group in this language, we choose
/// to provide a fully generic implementation.
///
/// However knowledge-soundness proofs are group dependent, and thus we can only assure security for
/// groups for which we know how to prove it.
///
/// In the paper, we have proved it for any prime known-order group; so it is safe to use with a
/// `PrimeOrderGroupElement`.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug, Eq)]
pub struct Language<Scalar, GroupElement> {
    _scalar_choice: PhantomData<Scalar>,
    _group_element_choice: PhantomData<GroupElement>,
}

impl<
    Scalar: group::GroupElement
    + Samplable
    + Mul<GroupElement, Output=GroupElement>
    + for<'r> Mul<&'r GroupElement, Output=GroupElement>
    + Copy,
    GroupElement: group::GroupElement,
> crate::Language<SOUND_PROOFS_REPETITIONS> for Language<Scalar, GroupElement>
{
    type WitnessSpaceGroupElement = Scalar;
    type StatementSpaceGroupElement = GroupElement;

    type PublicParameters = PublicParameters<
        Scalar::PublicParameters,
        GroupElement::PublicParameters,
        group::Value<GroupElement>,
    >;

    const NAME: &'static str = "Knowledge of the Discrete Log";

    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> Result<Self::StatementSpaceGroupElement> {
        let generator = GroupElement::new(
            language_public_parameters.generator,
            &language_public_parameters
                .groups_public_parameters
                .statement_space_public_parameters,
        )?;

        Ok(*witness * generator)
    }
}

/// The Public Parameters of the Knowledge of Discrete Log Maurer Language.
#[derive(Debug, PartialEq, Serialize, Clone)]
pub struct PublicParameters<ScalarPublicParameters, GroupPublicParameters, GroupElementValue> {
    pub groups_public_parameters:
    GroupsPublicParameters<ScalarPublicParameters, GroupPublicParameters>,
    pub generator: GroupElementValue,
}

impl<ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
PublicParameters<ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
{
    pub fn new<
        Scalar: group::GroupElement
        + Samplable
        + Mul<GroupElement, Output=GroupElement>
        + for<'r> Mul<&'r GroupElement, Output=GroupElement>
        + Copy,
        GroupElement,
    >(
        scalar_group_public_parameters: Scalar::PublicParameters,
        group_public_parameters: GroupElement::PublicParameters,
    ) -> Self
        where
            Scalar: group::GroupElement<PublicParameters=ScalarPublicParameters>,
            GroupElement: group::GroupElement<Value=GroupElementValue, PublicParameters=GroupPublicParameters>
            + CyclicGroupElement,
    {
        // TODO: maybe we don't want the generator all the time?
        let generator =
            GroupElement::generator_value_from_public_parameters(&group_public_parameters);
        Self {
            groups_public_parameters: GroupsPublicParameters {
                witness_space_public_parameters: scalar_group_public_parameters,
                statement_space_public_parameters: group_public_parameters,
            },
            generator,
        }
    }
}

impl<ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
AsRef<GroupsPublicParameters<ScalarPublicParameters, GroupPublicParameters>>
for PublicParameters<ScalarPublicParameters, GroupPublicParameters, GroupElementValue>
{
    fn as_ref(&self) -> &GroupsPublicParameters<ScalarPublicParameters, GroupPublicParameters> {
        &self.groups_public_parameters
    }
}

pub type Proof<Scalar, GroupElement, ProtocolContext> =
crate::Proof<SOUND_PROOFS_REPETITIONS, Language<Scalar, GroupElement>, ProtocolContext>;

#[cfg(any(test, feature = "benchmarking"))]
mod tests {
    use group::{GroupElement, secp256k1};
    use rand_core::OsRng;
    use rstest::rstest;

    use crate::{language, test_helpers};

    use super::*;

    pub(crate) type Lang = Language<secp256k1::Scalar, secp256k1::GroupElement>;

    pub(crate) fn language_public_parameters() -> language::PublicParameters<SOUND_PROOFS_REPETITIONS, Lang> {
        let secp256k1_scalar_public_parameters = secp256k1::scalar::PublicParameters::default();

        let secp256k1_group_public_parameters =
            secp256k1::group_element::PublicParameters::default();

        PublicParameters::new::<secp256k1::Scalar, secp256k1::GroupElement>(
            secp256k1_scalar_public_parameters,
            secp256k1_group_public_parameters,
        )
    }

    #[rstest]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    fn valid_proof_verifies(#[case] batch_size: usize) {
        let language_public_parameters = language_public_parameters();

        test_helpers::valid_proof_verifies::<SOUND_PROOFS_REPETITIONS, Lang>(
            language_public_parameters,
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

        // No invalid values as secp256k1 statically defines group,
        // `k256::AffinePoint` assures deserialized values are on curve,
        // and `Value` can only be instantiated through deserialization
        test_helpers::invalid_proof_fails_verification::<SOUND_PROOFS_REPETITIONS, Lang>(
            None,
            None,
            language_public_parameters,
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
        prover_public_parameters.generator = secp256k1::GroupElement::new(prover_public_parameters.generator, &secp256k1_group_public_parameters).unwrap().neutral().value();

        test_helpers::proof_over_invalid_public_parameters_fails_verification::<SOUND_PROOFS_REPETITIONS, Lang>(
            prover_public_parameters,
            verifier_public_parameters,
            batch_size,
            &mut OsRng,
        );
    }

    // TODO: other tests
}

#[cfg(feature = "benchmarking")]
mod benches {
    use criterion::Criterion;

    use crate::knowledge_of_discrete_log::tests::{Lang, language_public_parameters};
    use crate::proof;
    use crate::SOUND_PROOFS_REPETITIONS;

    pub(crate) fn benchmark(c: &mut Criterion) {
        let language_public_parameters = language_public_parameters();

        proof::benches::benchmark::<SOUND_PROOFS_REPETITIONS, Lang>(language_public_parameters.clone(), None, c);
    }
}
