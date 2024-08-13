// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub use language::Language;
pub use proof::{fischlin, Proof, BIT_SOUNDNESS_PROOFS_REPETITIONS, SOUND_PROOFS_REPETITIONS};

pub mod aggregation;
pub mod committment_of_discrete_log;
pub mod discrete_log_ratio_of_committed_values;
pub mod knowledge_of_decommitment;
pub mod knowledge_of_discrete_log;

pub mod language;
mod proof;

#[cfg(any(test, feature = "benchmarking"))]
#[allow(unused_imports)]
pub mod test_helpers {
    pub use crate::aggregation::test_helpers::*;
    pub use crate::language::test_helpers::*;
    pub use crate::proof::fischlin::test_helpers::*;
    pub use crate::proof::test_helpers::*;
}

/// Maurer error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("group error")]
    GroupInstantiation(#[from] group::Error),
    #[error("proof error")]
    Proof(#[from] ::proof::Error),
    #[error("commitment error")]
    Commitment(#[from] commitment::Error),
    #[error("aggregation error")]
    Aggregation(#[from] ::proof::aggregation::Error),
    #[error("unsupported repetitions")]
    UnsupportedRepetitions,
    #[error("invalid public parameters")]
    InvalidPublicParameters,
    #[error("invalid parameters")]
    InvalidParameters,
    #[error("serialization/deserialization error")]
    Serialization(#[from] serde_json::Error),
    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,
}

/// Maurer result.
pub type Result<T> = std::result::Result<T, Error>;

impl TryInto<::proof::aggregation::Error> for Error {
    type Error = Error;

    fn try_into(self) -> std::result::Result<::proof::aggregation::Error, Self::Error> {
        match self {
            Error::Aggregation(e) => Ok(e),
            e => Err(e),
        }
    }
}

#[cfg(feature = "benchmarking")]
criterion::criterion_group!(
    benches,
    knowledge_of_discrete_log::benches::benchmark,
    knowledge_of_decommitment::benches::benchmark,
    committment_of_discrete_log::benches::benchmark,
    discrete_log_ratio_of_committed_values::benches::benchmark,
);
