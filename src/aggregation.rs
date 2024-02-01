// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::{HashMap, HashSet};

use group::PartyID;

use crate::{language, Proof, Result};

pub mod commitment_round;
pub mod decommitment_round;
pub mod proof_share_round;
pub mod proof_aggregation_round;

pub type Output<const REPETITIONS: usize, Language, ProtocolContext> = (
    Proof<REPETITIONS, Language, ProtocolContext>,
    Vec<language::StatementSpaceGroupElement<REPETITIONS, Language>>,
);

fn process_incoming_messages<T>(party_id: PartyID, provers: &HashSet<PartyID>, messages: HashMap<PartyID, T>) -> Result<HashMap<PartyID, T>> {
    // First remove parties that didn't participate in the previous round, as they shouldn't be
    // allowed to join the session half-way, and we can self-heal this malicious behaviour
    // without needing to stop the session and report.
    let messages: HashMap<PartyID, _> = messages
        .into_iter()
        .filter(|(pid, _)| *pid != party_id)
        .filter(|(pid, _)| provers.contains(pid))
        .collect();

    let current_round_party_ids: HashSet<PartyID> = messages.keys().copied().collect();

    let unresponsive_parties: Vec<PartyID> = current_round_party_ids
        .symmetric_difference(provers)
        .cloned()
        .collect();

    if !unresponsive_parties.is_empty() {
        return Err(proof::aggregation::Error::UnresponsiveParties(unresponsive_parties))?;
    }

    Ok(messages)
}

pub(crate) mod tests {
    use std::collections::HashMap;
    use std::marker::PhantomData;

    use proof::aggregation::test_helpers::aggregates_internal;
    use rand_core::OsRng;

    use crate::Language;

    use super::*;

    #[allow(dead_code)]
    pub(crate) fn aggregates<const REPETITIONS: usize, Lang: Language<REPETITIONS>>(
        language_public_parameters: &Lang::PublicParameters,
        witnesses: Vec<Vec<Lang::WitnessSpaceGroupElement>>,
    ) {
        let number_of_parties = witnesses.len().try_into().unwrap();
        let provers = HashSet::from_iter(1..=number_of_parties);

        let commitment_round_parties: HashMap<
            PartyID,
            commitment_round::Party<REPETITIONS, Lang, PhantomData<()>>,
        > = witnesses
            .into_iter()
            .enumerate()
            .map(|(party_id, witnesses)| {
                let party_id: u16 = (party_id + 1).try_into().unwrap();
                (
                    party_id,
                    commitment_round::Party::new_session(
                        party_id,
                        provers.clone(),
                        language_public_parameters.clone(),
                        PhantomData,
                        witnesses,
                        &mut OsRng,
                    )
                        .unwrap(),
                )
            })
            .collect();

        let (proof, statements) = aggregates_internal(commitment_round_parties, &mut OsRng);

        assert!(
            proof
                .verify(&PhantomData, &language_public_parameters, statements)
                .is_ok(),
            "valid aggregated proofs should verify"
        );
    }
}