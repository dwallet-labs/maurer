// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::{HashMap, HashSet};

use group::PartyID;

use crate::{language, Proof, Result};

pub mod commitment_round;
pub mod decommitment_round;

pub type Output<const REPETITIONS: usize, Language, ProtocolContext> = (
    Proof<REPETITIONS, Language, ProtocolContext>,
    Vec<language::StatementSpaceGroupElement<REPETITIONS, Language>>,
);

fn process_incoming_messages<T>(party_id: PartyID, provers: HashSet<PartyID>, messages: HashMap<PartyID, T>) -> Result<HashMap<PartyID, T>> {
    // First remove parties that didn't participate in the previous round, as they shouldn't be
    // allowed to join the session half-way, and we can self-heal this malicious behaviour
    // without needing to stop the session and report.
    let messages: HashMap<PartyID, _> = messages
        .into_iter()
        .filter(|(pid, _)| *pid != party_id)
        .filter(|(pid, _)| provers.contains(pid))
        .collect();

    let current_round_party_ids: HashSet<PartyID> = messages.keys().copied().collect();

    let other_provers: HashSet<_> = provers.into_iter().filter(|pid| *pid != party_id).collect();

    let mut unresponsive_parties: Vec<PartyID> = other_provers
        .symmetric_difference(&current_round_party_ids)
        .cloned()
        .collect();

    unresponsive_parties.sort();

    if !unresponsive_parties.is_empty() {
        return Err(proof::aggregation::Error::UnresponsiveParties(unresponsive_parties))?;
    }

    Ok(messages)
}
