// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub use language::Language;
pub use proof::{BIT_SOUNDNESS_PROOFS_REPETITIONS, Proof, SOUND_PROOFS_REPETITIONS};

pub mod language;
mod proof;
pub mod knowledge_of_discrete_log;
mod discrete_log_ratio_of_committed_values;

pub mod test_helpers {
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


#[cfg(feature = "benchmarking")]
criterion::criterion_group!(
    benches,
    knowledge_of_discrete_log::benches::benchmark,
    discrete_log_ratio_of_committed_values::benches::benchmark,
);