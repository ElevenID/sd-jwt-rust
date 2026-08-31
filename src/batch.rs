//! Serial, cross-credential disclosure preprocessing contracts.
//!
//! This module provides the deterministic behavioral oracle for a future
//! bounded executor. It does not create threads and does not change the
//! existing single-credential verification path.
//!
//! # Trust boundary
//!
//! This API performs **untrusted preprocessing only**: it decodes, parses, and
//! hashes disclosure strings. It does not verify an issuer signature,
//! disclosure references, key binding, audience, nonce, time claims, or the
//! reconstructed claims. Callers must complete normal [`crate::SDJWTVerifier`]
//! verification and must never authorize from [`CredentialDisclosureMappings`].

use crate::disclosure_preprocessing::{
    assemble_disclosures, process_disclosure, DisclosureJob, DisclosureMappings, DisclosureOutcome,
    ProcessedDisclosure,
};
use crate::error::{Error, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_PLAN_ID: AtomicUsize = AtomicUsize::new(1);

/// The disclosures belonging to one credential, in caller-defined order.
#[derive(Clone, Copy)]
pub struct CredentialDisclosures<'a> {
    disclosures: &'a [String],
}

impl fmt::Debug for CredentialDisclosures<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialDisclosures")
            .field("disclosure_count", &self.disclosures.len())
            .finish()
    }
}

impl<'a> CredentialDisclosures<'a> {
    pub fn new(disclosures: &'a [String]) -> Self {
        Self { disclosures }
    }
}

/// Opaque identity for one credential within a batch plan.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CredentialBatchId {
    ordinal: usize,
}

impl fmt::Debug for CredentialBatchId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialBatchId")
            .field("ordinal", &self.ordinal)
            .finish()
    }
}

impl CredentialBatchId {
    pub fn ordinal(self) -> usize {
        self.ordinal
    }
}

/// Opaque composite identity for one disclosure job.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct DisclosureVerificationJobId {
    credential: CredentialBatchId,
    ordinal: usize,
}

impl fmt::Debug for DisclosureVerificationJobId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisclosureVerificationJobId")
            .field("credential_ordinal", &self.credential.ordinal)
            .field("job_ordinal", &self.ordinal)
            .finish()
    }
}

impl DisclosureVerificationJobId {
    pub fn credential(self) -> CredentialBatchId {
        self.credential
    }

    pub fn ordinal(self) -> usize {
        self.ordinal
    }
}

/// An immutable disclosure preprocessing job.
#[derive(Clone, Copy)]
pub struct DisclosureVerificationJob<'a> {
    plan_id: usize,
    id: DisclosureVerificationJobId,
    encoded_disclosure: &'a str,
}

impl fmt::Debug for DisclosureVerificationJob<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisclosureVerificationJob")
            .field("id", &self.id)
            .finish()
    }
}

impl<'a> DisclosureVerificationJob<'a> {
    pub fn id(&self) -> DisclosureVerificationJobId {
        self.id
    }

    /// Process this immutable job without shared mutable state.
    pub fn process(&self) -> DisclosureVerificationOutcome<'a> {
        let local_job = DisclosureJob {
            ordinal: self.id.ordinal,
            encoded_disclosure: self.encoded_disclosure,
        };
        let local_outcome = process_disclosure(&local_job);
        DisclosureVerificationOutcome {
            plan_id: self.plan_id,
            id: self.id,
            encoded_disclosure: self.encoded_disclosure,
            result: local_outcome.result,
        }
    }
}

/// An executor outcome whose identity remains bound to its originating job.
pub struct DisclosureVerificationOutcome<'a> {
    plan_id: usize,
    id: DisclosureVerificationJobId,
    encoded_disclosure: &'a str,
    result: Option<Result<ProcessedDisclosure>>,
}

impl fmt::Debug for DisclosureVerificationOutcome<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DisclosureVerificationOutcome")
            .field("id", &self.id)
            .field("has_result", &self.result.is_some())
            .finish()
    }
}

/// Executor contract for immutable cross-credential disclosure jobs.
pub trait DisclosureVerificationExecutor {
    fn execute<'a>(
        &self,
        jobs: &[DisclosureVerificationJob<'a>],
    ) -> Result<Vec<DisclosureVerificationOutcome<'a>>>;
}

/// The fail-fast, single-threaded behavioral oracle.
#[derive(Clone, Copy, Debug, Default)]
pub struct SerialDisclosureVerificationExecutor;

impl DisclosureVerificationExecutor for SerialDisclosureVerificationExecutor {
    fn execute<'a>(
        &self,
        jobs: &[DisclosureVerificationJob<'a>],
    ) -> Result<Vec<DisclosureVerificationOutcome<'a>>> {
        let mut outcomes = Vec::with_capacity(jobs.len());
        let mut credential = None;
        let mut observed_digests = HashSet::new();
        for job in jobs {
            if credential != Some(job.id.credential) {
                credential = Some(job.id.credential);
                observed_digests.clear();
            }
            let mut outcome = job.process();
            match outcome.result.take() {
                Some(Ok(processed)) => {
                    if !observed_digests.insert(processed.digest.clone()) {
                        return Err(Error::DuplicateDigestError(processed.digest));
                    }
                    outcome.result = Some(Ok(processed));
                    outcomes.push(outcome);
                }
                Some(Err(error)) => return Err(error),
                None => return Err(batch_contract_error("job returned no result")),
            }
        }
        Ok(outcomes)
    }
}

/// Untrusted preprocessing mappings for one credential.
///
/// Values are published only when the entire batch succeeds. These mappings
/// are not proof that a credential, disclosure, key binding, or claim is valid;
/// callers must not use them as authorization evidence.
#[derive(PartialEq)]
pub struct CredentialDisclosureMappings {
    credential_id: CredentialBatchId,
    hash_to_decoded_disclosure: HashMap<String, Value>,
    hash_to_disclosure: HashMap<String, String>,
    ordered_disclosure_digests: Vec<String>,
}

impl fmt::Debug for CredentialDisclosureMappings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialDisclosureMappings")
            .field("credential_id", &self.credential_id)
            .field("disclosure_count", &self.ordered_disclosure_digests.len())
            .finish()
    }
}

impl CredentialDisclosureMappings {
    pub fn credential_id(&self) -> CredentialBatchId {
        self.credential_id
    }

    pub fn decoded_disclosures(&self) -> &HashMap<String, Value> {
        &self.hash_to_decoded_disclosure
    }

    pub fn encoded_disclosures(&self) -> &HashMap<String, String> {
        &self.hash_to_disclosure
    }

    pub fn ordered_digests(&self) -> &[String] {
        &self.ordered_disclosure_digests
    }
}

/// Immutable plan for a caller-ordered collection of credentials.
pub struct DisclosureVerificationBatchPlan<'a> {
    plan_id: usize,
    credential_count: usize,
    disclosure_counts: Vec<usize>,
    jobs: Vec<DisclosureVerificationJob<'a>>,
}

impl<'a> DisclosureVerificationBatchPlan<'a> {
    pub fn new(credentials: &[CredentialDisclosures<'a>]) -> Result<Self> {
        let plan_id = NEXT_PLAN_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| {
                Error::InvalidState("Disclosure verification batch plan space exhausted".to_owned())
            })?;
        let disclosure_counts = credentials
            .iter()
            .map(|credential| credential.disclosures.len())
            .collect::<Vec<_>>();
        let total_jobs = disclosure_counts.iter().try_fold(0usize, |total, count| {
            total.checked_add(*count).ok_or_else(|| {
                Error::InvalidState("Disclosure verification batch size overflow".to_owned())
            })
        })?;
        let mut jobs = Vec::with_capacity(total_jobs);
        for (credential_ordinal, credential) in credentials.iter().enumerate() {
            let credential_id = CredentialBatchId {
                ordinal: credential_ordinal,
            };
            jobs.extend(credential.disclosures.iter().enumerate().map(
                |(disclosure_ordinal, encoded_disclosure)| DisclosureVerificationJob {
                    plan_id,
                    id: DisclosureVerificationJobId {
                        credential: credential_id,
                        ordinal: disclosure_ordinal,
                    },
                    encoded_disclosure,
                },
            ));
        }
        Ok(Self {
            plan_id,
            credential_count: credentials.len(),
            disclosure_counts,
            jobs,
        })
    }

    pub fn jobs(&self) -> &[DisclosureVerificationJob<'a>] {
        &self.jobs
    }

    /// Validate, restore, and atomically assemble all credential mappings.
    pub fn assemble(
        &self,
        mut outcomes: Vec<DisclosureVerificationOutcome<'a>>,
    ) -> Result<Vec<CredentialDisclosureMappings>> {
        outcomes.sort_by_key(|outcome| (outcome.id.credential.ordinal, outcome.id.ordinal));
        self.validate_outcomes(&outcomes)?;

        let mut outcomes = outcomes.into_iter();
        let mut assembled = Vec::with_capacity(self.credential_count);
        let mut job_offset = 0usize;
        for credential_ordinal in 0..self.credential_count {
            let count = self.disclosure_counts[credential_ordinal];
            let local_jobs = self.jobs[job_offset..job_offset + count]
                .iter()
                .map(|job| DisclosureJob {
                    ordinal: job.id.ordinal,
                    encoded_disclosure: job.encoded_disclosure,
                })
                .collect::<Vec<_>>();
            job_offset += count;
            let local_outcomes = outcomes
                .by_ref()
                .take(count)
                .map(|outcome| DisclosureOutcome {
                    ordinal: outcome.id.ordinal,
                    encoded_disclosure: outcome.encoded_disclosure,
                    result: outcome.result,
                })
                .collect();
            let DisclosureMappings {
                hash_to_decoded_disclosure,
                hash_to_disclosure,
                ordered_disclosure_digests,
            } = assemble_disclosures(&local_jobs, local_outcomes)?;
            assembled.push(CredentialDisclosureMappings {
                credential_id: CredentialBatchId {
                    ordinal: credential_ordinal,
                },
                hash_to_decoded_disclosure,
                hash_to_disclosure,
                ordered_disclosure_digests,
            });
        }
        Ok(assembled)
    }

    fn validate_outcomes(&self, outcomes: &[DisclosureVerificationOutcome<'_>]) -> Result<()> {
        if let Some(foreign) = outcomes
            .iter()
            .find(|outcome| outcome.plan_id != self.plan_id)
        {
            return Err(batch_contract_error(format!(
                "foreign plan identity at credential ordinal {} job ordinal {}",
                foreign.id.credential.ordinal, foreign.id.ordinal
            )));
        }
        for (expected, outcome) in self.jobs.iter().zip(outcomes.iter()) {
            if outcome.id != expected.id {
                return Err(batch_contract_error(format!(
                    "missing or duplicate outcome at credential ordinal {} job ordinal {}",
                    expected.id.credential.ordinal, expected.id.ordinal
                )));
            }
            if outcome.encoded_disclosure != expected.encoded_disclosure {
                return Err(batch_contract_error(format!(
                    "encoded identity changed at credential ordinal {} job ordinal {}",
                    expected.id.credential.ordinal, expected.id.ordinal
                )));
            }
        }
        if outcomes.len() != self.jobs.len() {
            let expected = self.jobs.get(outcomes.len()).map(|job| job.id);
            return Err(match expected {
                Some(id) => batch_contract_error(format!(
                    "no outcome at credential ordinal {} job ordinal {}",
                    id.credential.ordinal, id.ordinal
                )),
                None => batch_contract_error("unexpected extra outcome"),
            });
        }
        Ok(())
    }
}

/// Preprocess untrusted disclosures with the serial behavioral oracle.
///
/// This function does not verify credentials or claims. Pass the complete
/// presentation through [`crate::SDJWTVerifier`] before making trust decisions.
pub fn preprocess_disclosure_verification_batch(
    credentials: &[CredentialDisclosures<'_>],
) -> Result<Vec<CredentialDisclosureMappings>> {
    preprocess_disclosure_verification_batch_with_executor(
        credentials,
        &SerialDisclosureVerificationExecutor,
    )
}

/// Preprocess untrusted disclosures with a caller-provided executor contract.
///
/// This function does not verify credentials or claims. Pass the complete
/// presentation through [`crate::SDJWTVerifier`] before making trust decisions.
pub fn preprocess_disclosure_verification_batch_with_executor<E>(
    credentials: &[CredentialDisclosures<'_>],
    executor: &E,
) -> Result<Vec<CredentialDisclosureMappings>>
where
    E: DisclosureVerificationExecutor,
{
    let plan = DisclosureVerificationBatchPlan::new(credentials)?;
    let outcomes = executor.execute(plan.jobs())?;
    plan.assemble(outcomes)
}

fn batch_contract_error(message: impl Into<String>) -> Error {
    Error::InvalidState(format!(
        "Cross-credential disclosure executor contract violation: {}",
        message.into()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disclosure_preprocessing::preprocess_disclosures_serial;
    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    use crate::disclosure_preprocessing::{
        process_wide_disclosure_worker_budget, MAX_PARALLEL_WORKERS,
    };
    use serde_json::json;

    const OBJECT_DISCLOSURE: &str = "WyJzYWx0IiwibmFtZSIsIkFsaWNlIl0";
    const ARRAY_DISCLOSURE: &str = "WyJhcnJheS1zYWx0Iiw0Ml0";
    const PLAN_ID: usize = 987_654_321;

    fn owned(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn assert_redacted(debug: &str) {
        for sensitive in [
            OBJECT_DISCLOSURE,
            ARRAY_DISCLOSURE,
            "Alice",
            "secret-backend-error",
            "987654321",
        ] {
            assert!(
                !debug.contains(sensitive),
                "debug output leaked {sensitive}"
            );
        }
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn single_and_cross_credential_paths_share_native_worker_budget() {
        let single_credential = process_wide_disclosure_worker_budget();
        let cross_credential = process_wide_disclosure_worker_budget();

        assert!(std::ptr::eq(single_credential, cross_credential));
        assert_eq!(MAX_PARALLEL_WORKERS, 4);
    }

    #[test]
    fn every_public_debug_representation_is_redacted() {
        let disclosures = owned(&[OBJECT_DISCLOSURE]);
        let input = CredentialDisclosures::new(&disclosures);
        let credential_id = CredentialBatchId { ordinal: 7 };
        let job_id = DisclosureVerificationJobId {
            credential: credential_id,
            ordinal: 3,
        };
        let job = DisclosureVerificationJob {
            plan_id: PLAN_ID,
            id: job_id,
            encoded_disclosure: OBJECT_DISCLOSURE,
        };
        let outcome = DisclosureVerificationOutcome {
            plan_id: PLAN_ID,
            id: job_id,
            encoded_disclosure: OBJECT_DISCLOSURE,
            result: Some(Err(Error::InvalidDisclosure(
                "secret-backend-error".to_owned(),
            ))),
        };
        let mappings = CredentialDisclosureMappings {
            credential_id,
            hash_to_decoded_disclosure: HashMap::from([(
                "secret-digest".to_owned(),
                json!(["salt", "name", "Alice"]),
            )]),
            hash_to_disclosure: HashMap::from([(
                "secret-digest".to_owned(),
                OBJECT_DISCLOSURE.to_owned(),
            )]),
            ordered_disclosure_digests: vec!["secret-digest".to_owned()],
        };

        for debug in [
            format!("{input:?}"),
            format!("{credential_id:?}"),
            format!("{job_id:?}"),
            format!("{job:?}"),
            format!("{outcome:?}"),
            format!("{mappings:?}"),
        ] {
            assert_redacted(&debug);
        }
    }

    #[test]
    fn serial_batch_mappings_exactly_match_single_credential_oracle() {
        for disclosures in [Vec::new(), owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE])] {
            let expected = preprocess_disclosures_serial(&disclosures).unwrap();
            let actual = preprocess_disclosure_verification_batch(&[CredentialDisclosures::new(
                &disclosures,
            )])
            .unwrap()
            .pop()
            .unwrap();

            assert_eq!(
                actual.hash_to_decoded_disclosure,
                expected.hash_to_decoded_disclosure
            );
            assert_eq!(actual.hash_to_disclosure, expected.hash_to_disclosure);
            assert_eq!(
                actual.ordered_disclosure_digests,
                expected.ordered_disclosure_digests
            );
        }
    }

    #[test]
    fn serial_batch_error_precedence_exactly_matches_single_credential_oracle() {
        const INVALID_BASE64_DISCLOSURE: &str = "%";
        const INVALID_JSON_DISCLOSURE: &str = "ew";

        for disclosures in [
            owned(&[
                OBJECT_DISCLOSURE,
                OBJECT_DISCLOSURE,
                INVALID_JSON_DISCLOSURE,
            ]),
            owned(&[
                OBJECT_DISCLOSURE,
                OBJECT_DISCLOSURE,
                INVALID_BASE64_DISCLOSURE,
            ]),
            owned(&[
                INVALID_JSON_DISCLOSURE,
                OBJECT_DISCLOSURE,
                OBJECT_DISCLOSURE,
            ]),
            owned(&[
                INVALID_BASE64_DISCLOSURE,
                OBJECT_DISCLOSURE,
                OBJECT_DISCLOSURE,
            ]),
            owned(&[INVALID_JSON_DISCLOSURE, INVALID_BASE64_DISCLOSURE]),
            owned(&[INVALID_BASE64_DISCLOSURE, INVALID_JSON_DISCLOSURE]),
        ] {
            let expected = preprocess_disclosures_serial(&disclosures).unwrap_err();
            let actual = preprocess_disclosure_verification_batch(&[CredentialDisclosures::new(
                &disclosures,
            )])
            .unwrap_err();

            assert_eq!(
                std::mem::discriminant(&actual),
                std::mem::discriminant(&expected)
            );
            assert_eq!(actual.to_string(), expected.to_string());
        }
    }

    #[test]
    fn assembly_rejects_encoded_identity_drift_with_redacted_error() {
        let disclosures = owned(&[OBJECT_DISCLOSURE]);
        let plan =
            DisclosureVerificationBatchPlan::new(&[CredentialDisclosures::new(&disclosures)])
                .unwrap();
        let mut outcome = plan.jobs()[0].process();
        outcome.encoded_disclosure = ARRAY_DISCLOSURE;

        let error = plan.assemble(vec![outcome]).unwrap_err();

        assert_eq!(
            error.to_string(),
            "invalid state: Cross-credential disclosure executor contract violation: encoded identity changed at credential ordinal 0 job ordinal 0"
        );
        assert_redacted(&error.to_string());
    }

    #[test]
    fn assembly_rejects_missing_result_with_redacted_error() {
        let disclosures = owned(&[OBJECT_DISCLOSURE]);
        let plan =
            DisclosureVerificationBatchPlan::new(&[CredentialDisclosures::new(&disclosures)])
                .unwrap();
        let mut outcome = plan.jobs()[0].process();
        outcome.result = None;

        let error = plan.assemble(vec![outcome]).unwrap_err();

        assert_eq!(
            error.to_string(),
            "invalid state: Disclosure preprocessing executor contract violation: no preprocessing result was returned for ordinal 0"
        );
        assert_redacted(&error.to_string());
    }

    #[test]
    fn assembly_rejects_unexpected_extra_same_plan_outcome_with_redacted_error() {
        let disclosures = owned(&[OBJECT_DISCLOSURE]);
        let plan =
            DisclosureVerificationBatchPlan::new(&[CredentialDisclosures::new(&disclosures)])
                .unwrap();
        let outcomes = vec![plan.jobs()[0].process(), plan.jobs()[0].process()];

        let error = plan.assemble(outcomes).unwrap_err();

        assert_eq!(
            error.to_string(),
            "invalid state: Cross-credential disclosure executor contract violation: unexpected extra outcome"
        );
        assert_redacted(&error.to_string());
    }
}
