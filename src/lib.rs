// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub use language::Language;
pub use proof::Proof;

pub mod language;
mod proof;

/// Maurer error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("group error")]
    GroupInstantiation(#[from] group::Error),
    #[error("proof error")]
    Proof(#[from] ::proof::Error),
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
