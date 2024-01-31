use crate::{language, Proof};

// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
pub mod commitment_round;
pub mod decommitment_round;

pub type Output<const REPETITIONS: usize, Language, ProtocolContext> = (
    Proof<REPETITIONS, Language, ProtocolContext>,
    Vec<language::StatementSpaceGroupElement<REPETITIONS, Language>>,
);