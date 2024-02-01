// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::{HashMap, HashSet};

use crypto_bigint::rand_core::CryptoRngCore;
use group::GroupElement;
use group::helpers::FlatMapResults;
use group::PartyID;
use proof::aggregation::ProofAggregationRoundParty;
use serde::Serialize;

use crate::{Error, Proof, Result};
use crate::aggregation::{Output, process_incoming_messages};
use crate::aggregation::proof_share_round::ProofShare;
use crate::language::GroupsPublicParametersAccessors;
use crate::proof::ChallengeSizedNumber;

#[cfg_attr(feature = "benchmarking", derive(Clone))]
pub struct Party<
    // Number of times this proof should be repeated to achieve sufficient security
    const REPETITIONS: usize,
    // The language we are proving
    Language: crate::Language<REPETITIONS>,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript
    ProtocolContext: Clone,
> {
    pub(super) party_id: PartyID,
    pub(crate) provers: HashSet<PartyID>,
    pub(super) language_public_parameters: Language::PublicParameters,
    pub(super) protocol_context: ProtocolContext,
    pub(super) statement_masks: HashMap<PartyID, [group::Value<Language::StatementSpaceGroupElement>; REPETITIONS]>,
    pub(super) aggregated_statements: Vec<Language::StatementSpaceGroupElement>,
    pub(super) aggregated_statement_masks: [Language::StatementSpaceGroupElement; REPETITIONS],
    pub(super) responses: [Language::WitnessSpaceGroupElement; REPETITIONS],
}

impl<
    const REPETITIONS: usize,
    Language: crate::Language<REPETITIONS>,
    ProtocolContext: Clone + Serialize,
> ProofAggregationRoundParty<Output<REPETITIONS, Language, ProtocolContext>>
for Party<REPETITIONS, Language, ProtocolContext>
{
    type Error = Error;
    type ProofShare = ProofShare<REPETITIONS, Language>;

    fn aggregate_proof_shares(
        self,
        proof_shares: HashMap<PartyID, Self::ProofShare>,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<Output<REPETITIONS, Language, ProtocolContext>> {
        let proof_shares = process_incoming_messages(self.party_id, &self.provers, proof_shares)?;

        let proof_shares: HashMap<
            PartyID,
            group::Result<[Language::WitnessSpaceGroupElement; REPETITIONS]>,
        > = proof_shares
            .into_iter()
            .map(|(party_id, proof_share)| {
                (
                    party_id,
                    proof_share
                        .0
                        .map(|value| {
                            Language::WitnessSpaceGroupElement::new(
                                value,
                                &self
                                    .language_public_parameters
                                    .witness_space_public_parameters(),
                            )
                        })
                        .flat_map_results(),
                )
            })
            .collect();

        let parties_sending_invalid_proof_shares: Vec<PartyID> = proof_shares
            .iter()
            .filter(|(_, proof_share)| proof_share.is_err())
            .map(|(party_id, _)| *party_id)
            .collect();

        if !parties_sending_invalid_proof_shares.is_empty() {
            return Err(proof::aggregation::Error::InvalidProofShare(
                parties_sending_invalid_proof_shares,
            ))?;
        }

        let proof_shares: HashMap<PartyID, [Language::WitnessSpaceGroupElement; REPETITIONS]> =
            proof_shares
                .into_iter()
                .map(|(party_id, proof_share)| (party_id, proof_share.unwrap()))
                .collect();

        let responses =
            proof_shares
                .values()
                .fold(Ok(self.responses), |aggregated_responses, proof_share| {
                    aggregated_responses.and_then(|aggregated_responses| {
                        aggregated_responses
                            .into_iter()
                            .zip(proof_share)
                            .map(|(aggregated_response, response)| aggregated_response + response)
                            .collect::<Vec<_>>()
                            .try_into()
                            .map_err(|_| Error::InternalError)
                    })
                })?.map(|response| response.value());

        let aggregated_statement_masks = self.aggregated_statement_masks.map(|statement_mask| statement_mask.value());
        let aggregated_proof = Proof::new(aggregated_statement_masks, responses);
        if aggregated_proof
            .verify(
                &self.protocol_context,
                &self.language_public_parameters,
                self.aggregated_statements.clone(),
            )
            .is_err()
        {
            /*
               Identifiable abort logic: using the challenges of the aggregated proof, validate the individual proofs
               (i.e. proof share, statement mask produced by every party).
            */
            let mut transcript = Proof::<REPETITIONS, Language, ProtocolContext>::setup_transcript(
                &self.protocol_context,
                &self.language_public_parameters,
                self.aggregated_statements.iter()
                    .map(|statement| statement.value())
                    .collect(),
                &aggregated_statement_masks,
            )?;

            let challenges: [Vec<ChallengeSizedNumber>; REPETITIONS] =
                Proof::<REPETITIONS, Language, ProtocolContext>::compute_challenges(self.aggregated_statements.len(), &mut transcript);

            let proofs: HashMap<_, _> = proof_shares
                .into_iter()
                .map(|(party_id, proof_share)| {
                    self.statement_masks.get(&party_id).map(|&statement_masks| (
                        party_id,
                        Proof::<REPETITIONS, Language, ProtocolContext>::new(
                            statement_masks,
                            proof_share.map(|share| share.value()),
                        ),
                    )).ok_or(Error::InternalError) // Same parties participating in all rounds.
                }).collect::<Result<_>>()?;

            let proof_share_cheating_parties: Vec<PartyID> =
                proofs.into_iter().filter(|(_, proof)| {
                    proof
                        .verify_inner(
                            challenges.clone(),
                            &self.language_public_parameters,
                            self.aggregated_statements.clone(),
                        )
                        .is_err()
                })
                    .map(|(party_id, _)| party_id)
                    .collect();

            return Err(proof::aggregation::Error::ProofShareVerification(
                proof_share_cheating_parties,
            ))?;
        }

        Ok((aggregated_proof, self.aggregated_statements))
    }
}
