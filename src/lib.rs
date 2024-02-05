// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub use language::Language;
pub use proof::{BIT_SOUNDNESS_PROOFS_REPETITIONS, Proof, SOUND_PROOFS_REPETITIONS};

pub mod language;
mod proof;
pub mod committment_of_discrete_log;
pub mod aggregation;
pub mod knowledge_of_discrete_log;

#[cfg(feature = "test_helpers")]
pub mod test_helpers {
    pub use crate::aggregation::test_helpers::*;
    pub use crate::language::test_helpers::*;
    pub use crate::proof::test_helpers::*;
}

/// Maurer error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("group error")]
    GroupInstantiation(#[from] group::Error),
    #[error("proof error")]
    Proof(#[from] ::proof::Error),
    #[error("aggregation error")]
    Aggregation(#[from] ::proof::aggregation::Error),
    #[error("commitment error")]
    Commitment(#[from] commitment::Error),
    #[error("unsupported repetitions: must be either 1 or 128")]
    UnsupportedRepetitions,
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
            e => Err(e)
        }
    }
}

#[cfg(feature = "benchmarking")]
criterion::criterion_group!(
    benches,
    knowledge_of_discrete_log::benches::benchmark,
    committment_of_discrete_log::benches::benchmark
);