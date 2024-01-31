// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crate::{language, Proof};

pub mod commitment_round;
pub mod decommitment_round;
pub mod proof_share_round;
pub mod proof_aggregation_round;

pub type Output<const REPETITIONS: usize, Language, ProtocolContext> = (
    Proof<REPETITIONS, Language, ProtocolContext>,
    Vec<language::StatementSpaceGroupElement<REPETITIONS, Language>>,
);