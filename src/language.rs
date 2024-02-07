// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use core::fmt::Debug;

use group::{ComputationalSecuritySizedNumber, GroupElement, Samplable};
use serde::{Deserialize, Serialize};

use crate::{
    proof::{BIT_SOUNDNESS_PROOFS_REPETITIONS, SOUND_PROOFS_REPETITIONS},
    Result,
};

/// A Maurer Zero-Knowledge Proof Language.
///
/// Can be generically used to generate a batched Maurer zero-knowledge `Proof`.
/// As defined in Appendix B. Maurer Protocols in the paper.
pub trait Language<
    // Number of times maurer proof parallel repetitions needed
    // to achieve sufficiently small knowledge soundness error.
    const REPETITIONS: usize,
>: Clone + PartialEq + Eq + Debug {
    /// An element of the witness space $(\HH_\pp, +)$
    type WitnessSpaceGroupElement: GroupElement + Samplable;

    /// An element in the associated statement space $(\GG_\pp, \cdot)$,
    type StatementSpaceGroupElement: GroupElement;

    /// Public parameters for a language family $\pp \gets \Setup(1^\kappa)$.
    ///
    /// Includes the public parameters of the witness and statement groups.
    ///
    /// Group public parameters are encoded separately in
    /// `WitnessSpaceGroupElement::PublicParameters` and
    /// `StatementSpaceGroupElement::PublicParameters`.
    type PublicParameters: AsRef<
        GroupsPublicParameters<
            group::PublicParameters<Self::WitnessSpaceGroupElement>,
            group::PublicParameters<Self::StatementSpaceGroupElement>,
        >,
    > + Serialize
    + PartialEq
    + Clone;

    /// A unique string representing the name of this language; will be inserted to the Fiat-Shamir
    /// transcript.
    const NAME: &'static str;

    /// The number of bits to use for the challenge (per repetition).
    fn challenge_bits() -> Result<usize> {
        if REPETITIONS == SOUND_PROOFS_REPETITIONS {
            Ok(ComputationalSecuritySizedNumber::BITS)
        } else if REPETITIONS == BIT_SOUNDNESS_PROOFS_REPETITIONS {
            Ok(1)
        } else {
            Err(crate::Error::UnsupportedRepetitions)
        }
    }

    /// A group homomorphism $\phi:\HH\to\GG$ from $(\HH_\pp, +)$, the witness space,
    /// to $(\GG_\pp,\cdot)$, the statement space.
    ///
    /// The name of this method, `homomorphose` is inspired by the wonderful book
    /// "Gödel, Escher, Bach: An Eternal Golden Braid", by Douglas R. Hofstadter, and specifically,
    /// Escher's painting ["Metamorphosis II"](https://www.digitalcommonwealth.org/search/commonwealth:ww72cb78j), 
    /// in which the theme `METAMORPHOSE` is central.
    fn homomorphose(
        witness: &Self::WitnessSpaceGroupElement,
        language_public_parameters: &Self::PublicParameters,
    ) -> Result<Self::StatementSpaceGroupElement>;
}

pub type PublicParameters<const REPETITIONS: usize, L> =
    <L as Language<REPETITIONS>>::PublicParameters;

pub type WitnessSpaceGroupElement<const REPETITIONS: usize, L> =
    <L as Language<REPETITIONS>>::WitnessSpaceGroupElement;

pub type WitnessSpacePublicParameters<const REPETITIONS: usize, L> =
    group::PublicParameters<WitnessSpaceGroupElement<REPETITIONS, L>>;

pub type WitnessSpaceValue<const REPETITIONS: usize, L> =
    group::Value<WitnessSpaceGroupElement<REPETITIONS, L>>;

pub type StatementSpaceGroupElement<const REPETITIONS: usize, L> =
    <L as Language<REPETITIONS>>::StatementSpaceGroupElement;

pub type StatementSpacePublicParameters<const REPETITIONS: usize, L> =
    group::PublicParameters<StatementSpaceGroupElement<REPETITIONS, L>>;

pub type StatementSpaceValue<const REPETITIONS: usize, L> =
    group::Value<StatementSpaceGroupElement<REPETITIONS, L>>;

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters> {
    pub witness_space_public_parameters: WitnessSpacePublicParameters,
    pub statement_space_public_parameters: StatementSpacePublicParameters,
}

pub trait GroupsPublicParametersAccessors<
    'a,
    WitnessSpacePublicParameters: 'a,
    StatementSpacePublicParameters: 'a,
>:
    AsRef<GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>>
{
    fn witness_space_public_parameters(&'a self) -> &'a WitnessSpacePublicParameters {
        &self.as_ref().witness_space_public_parameters
    }

    fn statement_space_public_parameters(&'a self) -> &'a StatementSpacePublicParameters {
        &self.as_ref().statement_space_public_parameters
    }
}

impl<
        'a,
        WitnessSpacePublicParameters: 'a,
        StatementSpacePublicParameters: 'a,
        T: AsRef<GroupsPublicParameters<WitnessSpacePublicParameters, StatementSpacePublicParameters>>,
    >
    GroupsPublicParametersAccessors<
        'a,
        WitnessSpacePublicParameters,
        StatementSpacePublicParameters,
    > for T
{
}

#[cfg(feature = "test_helpers")]
pub(super) mod test_helpers {
    use core::iter;

    use crypto_bigint::rand_core::CryptoRngCore;

    use super::*;

    pub fn sample_witnesses<const REPETITIONS: usize, Lang: Language<REPETITIONS>>(
        language_public_parameters: &Lang::PublicParameters,
        batch_size: usize,
        rng: &mut impl CryptoRngCore,
    ) -> Vec<Lang::WitnessSpaceGroupElement> {
        iter::repeat_with(|| {
            Lang::WitnessSpaceGroupElement::sample(
                language_public_parameters.witness_space_public_parameters(),
                rng,
            )
            .unwrap()
        })
        .take(batch_size)
        .collect()
    }

    pub fn sample_witness<const REPETITIONS: usize, Lang: Language<REPETITIONS>>(
        language_public_parameters: &Lang::PublicParameters,
        rng: &mut impl CryptoRngCore,
    ) -> Lang::WitnessSpaceGroupElement {
        let witnesses = sample_witnesses::<REPETITIONS, Lang>(language_public_parameters, 1, rng);

        witnesses.first().unwrap().clone()
    }
}
