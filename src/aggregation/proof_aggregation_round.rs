// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::{HashMap, HashSet};

use crypto_bigint::rand_core::CryptoRngCore;
use group::helpers::FlatMapResults;
use group::PartyID;
use group::{ComputationalSecuritySizedNumber, GroupElement};
use proof::aggregation::{process_incoming_messages, ProofAggregationRoundParty};
use serde::Serialize;

use crate::aggregation::proof_share_round::ProofShare;
use crate::aggregation::Output;
use crate::language::GroupsPublicParametersAccessors;
use crate::{Error, Proof, Result};

#[cfg_attr(any(test, feature = "test_helpers"), derive(Clone))]
pub struct Party<
    // Number of times this proof should be repeated to achieve sufficient security.
    const REPETITIONS: usize,
    // The language we are proving.
    Language: crate::Language<REPETITIONS>,
    // A struct used by the protocol using this proof,
    // used to provide extra necessary context that will parameterize the proof (and thus verifier
    // code) and be inserted to the Fiat-Shamir transcript.
    ProtocolContext: Clone,
> {
    pub(super) party_id: PartyID,
    pub(crate) provers: HashSet<PartyID>,
    pub(super) language_public_parameters: Language::PublicParameters,
    pub(super) protocol_context: ProtocolContext,
    pub(super) statement_masks:
        HashMap<PartyID, [group::Value<Language::StatementSpaceGroupElement>; REPETITIONS]>,
    pub statements: HashMap<PartyID, Vec<Language::StatementSpaceGroupElement>>,
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
        let proof_shares =
            process_incoming_messages(self.party_id, self.provers, proof_shares, true)?;

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
                                self.language_public_parameters
                                    .witness_space_public_parameters(),
                            )
                        })
                        .flat_map_results(),
                )
            })
            .collect();

        let mut parties_sending_invalid_proof_shares: Vec<PartyID> = proof_shares
            .iter()
            .filter(|(_, proof_share)| proof_share.is_err())
            .map(|(party_id, _)| *party_id)
            .collect();
        parties_sending_invalid_proof_shares.sort();

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

        let aggregated_responses =
            Language::WitnessSpaceGroupElement::batch_normalize_const_generic(
                proof_shares.values().try_fold(
                    self.responses,
                    |aggregated_responses, proof_share| {
                        aggregated_responses
                            .into_iter()
                            .zip(proof_share)
                            .map(|(aggregated_response, response)| aggregated_response + response)
                            .collect::<Vec<_>>()
                            .try_into()
                            .map_err(|_| Error::InternalError)
                    },
                )?,
            );

        let aggregated_statement_masks =
            Language::StatementSpaceGroupElement::batch_normalize_const_generic(
                self.aggregated_statement_masks,
            );
        let aggregated_proof = Proof::new(aggregated_statement_masks, aggregated_responses);
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
                Language::StatementSpaceGroupElement::batch_normalize(
                    self.aggregated_statements.clone(),
                ),
                &aggregated_statement_masks,
            )?;

            let challenges: [Vec<ComputationalSecuritySizedNumber>; REPETITIONS] =
                Proof::<REPETITIONS, Language, ProtocolContext>::compute_challenges(
                    self.aggregated_statements.len(),
                    &mut transcript,
                );

            let proofs: HashMap<_, _> = proof_shares
                .into_iter()
                .map(|(party_id, proof_share)| {
                    (
                        party_id,
                        Proof::<REPETITIONS, Language, ProtocolContext>::new(
                            // Same parties participating in all rounds, safe to `.unwrap()`.
                            *self.statement_masks.get(&party_id).unwrap(),
                            Language::WitnessSpaceGroupElement::batch_normalize_const_generic(
                                proof_share,
                            ),
                        ),
                    )
                })
                .collect();

            let mut proof_share_cheating_parties: Vec<PartyID> = proofs
                .into_iter()
                .filter(|(party_id, proof)| {
                    proof
                        .verify_inner(
                            challenges.clone(),
                            &self.language_public_parameters,
                            // Same parties participating in all rounds, safe to `.unwrap()`.
                            self.statements.get(party_id).unwrap().clone(),
                        )
                        .is_err()
                })
                .map(|(party_id, _)| party_id)
                .collect();
            proof_share_cheating_parties.sort();

            return Err(proof::aggregation::Error::ProofShareVerification(
                proof_share_cheating_parties,
            ))?;
        }

        Ok((aggregated_proof, self.aggregated_statements))
    }
}
