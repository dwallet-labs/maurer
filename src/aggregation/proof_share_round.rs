// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use std::collections::{HashMap, HashSet};

use crypto_bigint::rand_core::CryptoRngCore;
use group::{GroupElement, PartyID};
use group::helpers::FlatMapResults;
use proof::aggregation::ProofShareRoundParty;
use serde::{Deserialize, Serialize};

use commitment::Commitment;

use crate::{Error, Result};
use crate::aggregation::{process_incoming_messages, proof_aggregation_round};
use crate::aggregation::decommitment_round::Decommitment;
use crate::language::GroupsPublicParametersAccessors;
use crate::language::WitnessSpaceValue;
use crate::Proof;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProofShare<const REPETITIONS: usize, Language: crate::Language<REPETITIONS>>(
    #[serde(with = "group::helpers::const_generic_array_serialization")]
    pub(super) [WitnessSpaceValue<REPETITIONS, Language>; REPETITIONS],
);

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
    pub(super) witnesses: Vec<Language::WitnessSpaceGroupElement>,
    pub(super) statements: Vec<Language::StatementSpaceGroupElement>,
    pub(super) randomizers: [Language::WitnessSpaceGroupElement; REPETITIONS],
    pub(super) statement_masks: [Language::StatementSpaceGroupElement; REPETITIONS],
    pub(super) commitments: HashMap<PartyID, Commitment>,
}

impl<
    const REPETITIONS: usize,
    Language: crate::Language<REPETITIONS>,
    ProtocolContext: Clone + Serialize,
> ProofShareRoundParty<super::Output<REPETITIONS, Language, ProtocolContext>>
for Party<REPETITIONS, Language, ProtocolContext>
{
    type Error = Error;
    type Decommitment = Decommitment<REPETITIONS, Language>;
    type ProofShare = ProofShare<REPETITIONS, Language>;
    type ProofAggregationRoundParty =
    proof_aggregation_round::Party<REPETITIONS, Language, ProtocolContext>;

    fn generate_proof_share(
        self,
        decommitments: HashMap<PartyID, Self::Decommitment>,
        _rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ProofShare, Self::ProofAggregationRoundParty)> {
        let decommitments = process_incoming_messages(self.party_id, self.provers.clone(), decommitments)?;

        let reconstructed_commitments: Result<HashMap<PartyID, Commitment>> = decommitments
            .iter()
            .map(|(party_id, decommitment)| {
                Proof::<REPETITIONS, Language, ProtocolContext>::setup_transcript(
                    &self.protocol_context,
                    &self.language_public_parameters,
                    decommitment.statements.clone(),
                    &decommitment.statement_masks,
                )
                    .map(|mut transcript| {
                        (
                            *party_id,
                            Commitment::commit_transcript(
                                *party_id,
                                "maurer proof aggregation - commitment round commitment".to_string(),
                                &mut transcript,
                                &decommitment.commitment_randomness,
                            ),
                        )
                    })
            })
            .collect();

        let reconstructed_commitments: HashMap<PartyID, Commitment> = reconstructed_commitments?;

        let miscommitting_parties: Vec<PartyID> = decommitments.keys().cloned()
            .filter(|party_id| reconstructed_commitments[party_id] != self.commitments[party_id])
            .collect();

        if !miscommitting_parties.is_empty() {
            return Err(proof::aggregation::Error::WrongDecommitment(miscommitting_parties))?;
        }

        let statement_masks: group::Result<
            Vec<[Language::StatementSpaceGroupElement; REPETITIONS]>,
        > = decommitments
            .values()
            .map(|decommitment| {
                decommitment
                    .statement_masks
                    .map(|statement_mask| {
                        Language::StatementSpaceGroupElement::new(
                            statement_mask,
                            &self
                                .language_public_parameters
                                .statement_space_public_parameters(),
                        )
                    })
                    .flat_map_results()
            })
            .collect();

        let number_of_statements = self.statements.len();

        let parties_committed_on_wrong_number_of_statements: Vec<PartyID> = decommitments
            .iter()
            .filter(|(_, decommitment)| decommitment.statements.len() != number_of_statements)
            .map(|(party_id, _)| *party_id)
            .collect();

        if !parties_committed_on_wrong_number_of_statements.is_empty() {
            return Err(proof::aggregation::Error::WrongNumberOfDecommittedStatements(
                miscommitting_parties,
            ))?;
        }

        let aggregated_statement_masks = statement_masks?.into_iter().fold(
            Ok(self.statement_masks),
            |aggregated_statement_masks, statement_masks| {
                aggregated_statement_masks.and_then(|aggregated_statement_masks| {
                    aggregated_statement_masks
                        .into_iter()
                        .zip(statement_masks)
                        .map(|(aggregated_statement_mask, statement_mask)| {
                            aggregated_statement_mask + statement_mask
                        })
                        .collect::<Vec<_>>()
                        .try_into()
                        .map_err(|_| Error::InternalError)
                })
            },
        )?;

        let statements_vector: group::Result<Vec<Vec<Language::StatementSpaceGroupElement>>> =
            decommitments
                .clone()
                .into_values()
                .map(|decommitment| {
                    decommitment
                        .statements
                        .into_iter()
                        .map(|statement_value| {
                            Language::StatementSpaceGroupElement::new(
                                statement_value,
                                &self
                                    .language_public_parameters
                                    .statement_space_public_parameters(),
                            )
                        })
                        .collect()
                })
                .collect();

        let statements_vector = statements_vector?;

        let aggregated_statements: Vec<Language::StatementSpaceGroupElement> = (0
            ..number_of_statements)
            .map(|i| {
                statements_vector
                    .iter()
                    .map(|statements| statements[i].clone())
                    .fold(
                        self.statements[i].clone(),
                        |aggregated_group_element, statement| aggregated_group_element + statement,
                    )
            })
            .collect();

        let responses = Proof::<REPETITIONS, Language, ProtocolContext>::prove_inner(
            &self.protocol_context,
            &self.language_public_parameters,
            self.witnesses,
            aggregated_statements.clone(),
            self.randomizers,
            aggregated_statement_masks.clone(),
        )?
            .responses;

        let proof_share = ProofShare(responses);

        let responses = responses
            .map(|value| {
                Language::WitnessSpaceGroupElement::new(
                    value,
                    &self
                        .language_public_parameters
                        .witness_space_public_parameters(),
                )
            })
            .flat_map_results()?;

        let statement_masks = decommitments
            .into_iter()
            .map(|(party_id, decommitment)|
                (party_id, decommitment
                    .statement_masks)).collect();

        let proof_aggregation_round_party =
            proof_aggregation_round::Party::<REPETITIONS, Language, ProtocolContext> {
                party_id: self.party_id,
                provers: self.provers,
                language_public_parameters: self.language_public_parameters,
                protocol_context: self.protocol_context,
                statement_masks,
                aggregated_statements,
                aggregated_statement_masks,
                responses,
            };

        Ok((proof_share, proof_aggregation_round_party))
    }
}
