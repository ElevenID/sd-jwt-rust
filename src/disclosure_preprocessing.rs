// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use crate::utils::{base64_hash, base64url_decode};
use serde_json::Value;
use std::collections::HashMap;

/// An immutable unit of disclosure preprocessing work.
///
/// The ordinal determines legacy error and duplicate-detection precedence. The
/// encoded disclosure is also carried as identity so assembly can reject a
/// result that was associated with the wrong input.
#[derive(Debug)]
struct DisclosureJob<'a> {
    ordinal: usize,
    encoded_disclosure: &'a str,
}

#[derive(Debug)]
struct ProcessedDisclosure {
    digest: String,
    decoded_disclosure: Value,
}

/// A worker outcome retains identity even when decoding or parsing fails.
#[derive(Debug)]
struct DisclosureOutcome<'a> {
    ordinal: usize,
    encoded_disclosure: &'a str,
    result: Result<ProcessedDisclosure>,
}

trait DisclosureExecutor {
    fn execute<'a>(&self, jobs: &[DisclosureJob<'a>]) -> Vec<DisclosureOutcome<'a>>;
}

/// The behavioral oracle. Production remains serial until an optimized
/// executor can be compared against this implementation.
struct SerialDisclosureExecutor;

impl DisclosureExecutor for SerialDisclosureExecutor {
    fn execute<'a>(&self, jobs: &[DisclosureJob<'a>]) -> Vec<DisclosureOutcome<'a>> {
        jobs.iter().map(process_disclosure).collect()
    }
}

#[derive(Debug)]
pub(super) struct DisclosureMappings {
    pub(super) hash_to_decoded_disclosure: HashMap<String, Value>,
    pub(super) hash_to_disclosure: HashMap<String, String>,
}

pub(super) fn preprocess_disclosures(encoded_disclosures: &[String]) -> Result<DisclosureMappings> {
    let jobs = plan_disclosures(encoded_disclosures);
    let outcomes = SerialDisclosureExecutor.execute(&jobs);
    assemble_disclosures(&jobs, outcomes)
}

fn plan_disclosures(encoded_disclosures: &[String]) -> Vec<DisclosureJob<'_>> {
    encoded_disclosures
        .iter()
        .enumerate()
        .map(|(ordinal, encoded_disclosure)| DisclosureJob {
            ordinal,
            encoded_disclosure,
        })
        .collect()
}

/// Decode, parse, and hash one disclosure without reading or mutating shared
/// state. Hashing deliberately uses the original encoded bytes.
fn process_disclosure<'a>(job: &DisclosureJob<'a>) -> DisclosureOutcome<'a> {
    let result = (|| {
        let decoded_disclosure = base64url_decode(job.encoded_disclosure).map_err(|err| {
            Error::InvalidDisclosure(format!(
                "Error decoding disclosure {}: {}",
                job.encoded_disclosure, err
            ))
        })?;
        let decoded_disclosure = serde_json::from_slice(&decoded_disclosure).map_err(|err| {
            Error::InvalidDisclosure(format!(
                "Error parsing disclosure {}: {}",
                job.encoded_disclosure, err
            ))
        })?;

        Ok(ProcessedDisclosure {
            digest: base64_hash(job.encoded_disclosure.as_bytes()),
            decoded_disclosure,
        })
    })();

    DisclosureOutcome {
        ordinal: job.ordinal,
        encoded_disclosure: job.encoded_disclosure,
        result,
    }
}

/// Restore worker outcomes to input order, validate the executor contract, and
/// only then publish complete mappings. Any failure discards all partial state.
fn assemble_disclosures<'a>(
    jobs: &[DisclosureJob<'a>],
    mut outcomes: Vec<DisclosureOutcome<'a>>,
) -> Result<DisclosureMappings> {
    outcomes.sort_by_key(|outcome| outcome.ordinal);
    validate_outcome_contract(jobs, &outcomes)?;

    let mut hash_to_decoded_disclosure = HashMap::with_capacity(jobs.len());
    let mut hash_to_disclosure = HashMap::with_capacity(jobs.len());

    for outcome in outcomes {
        let processed = outcome.result?;
        if hash_to_decoded_disclosure.contains_key(&processed.digest) {
            return Err(Error::DuplicateDigestError(processed.digest));
        }

        hash_to_disclosure.insert(
            processed.digest.clone(),
            outcome.encoded_disclosure.to_owned(),
        );
        hash_to_decoded_disclosure.insert(processed.digest, processed.decoded_disclosure);
    }

    Ok(DisclosureMappings {
        hash_to_decoded_disclosure,
        hash_to_disclosure,
    })
}

fn validate_outcome_contract(
    jobs: &[DisclosureJob<'_>],
    outcomes: &[DisclosureOutcome<'_>],
) -> Result<()> {
    for (expected_ordinal, job) in jobs.iter().enumerate() {
        if job.ordinal != expected_ordinal {
            return Err(executor_contract_error(format!(
                "job ordinal {} does not match planned ordinal {expected_ordinal}",
                job.ordinal
            )));
        }
    }

    if let Some(outcome) = outcomes
        .iter()
        .find(|outcome| outcome.ordinal >= jobs.len())
    {
        return Err(executor_contract_error(format!(
            "outcome ordinal {} is out of range for {} jobs",
            outcome.ordinal,
            jobs.len()
        )));
    }

    if let Some(duplicate) = outcomes
        .windows(2)
        .find(|pair| pair[0].ordinal == pair[1].ordinal)
    {
        return Err(executor_contract_error(format!(
            "multiple outcomes were returned for ordinal {}",
            duplicate[0].ordinal
        )));
    }

    for (expected_ordinal, outcome) in outcomes.iter().enumerate() {
        if outcome.ordinal != expected_ordinal {
            return Err(executor_contract_error(format!(
                "no outcome was returned for ordinal {expected_ordinal}"
            )));
        }

        if outcome.encoded_disclosure != jobs[expected_ordinal].encoded_disclosure {
            return Err(executor_contract_error(format!(
                "encoded identity changed for ordinal {expected_ordinal}"
            )));
        }
    }

    if outcomes.len() < jobs.len() {
        return Err(executor_contract_error(format!(
            "no outcome was returned for ordinal {}",
            outcomes.len()
        )));
    }

    Ok(())
}

fn executor_contract_error(message: String) -> Error {
    Error::InvalidState(format!(
        "Disclosure preprocessing executor contract violation: {message}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const OBJECT_DISCLOSURE: &str = "WyJzYWx0IiwibmFtZSIseyJyb2xlIjoiYWRtaW4ifV0";
    const OBJECT_DISCLOSURE_HASH: &str = "UIToslcm0Y9tZh7-6HTCY9UQjI_duhh-wnQtQX9yfqQ";
    const ARRAY_DISCLOSURE: &str = "WyJhcnJheS1zYWx0Iiw0Ml0";
    const ARRAY_DISCLOSURE_HASH: &str = "GiEJkgij2cXW0bIMz3Fwi09P0ZQLSXzQ-1CpxGGfl98";
    const WHITESPACE_DISCLOSURE: &str = "WyJzYWx0IiwgIm5hbWUiLCB7InJvbGUiOiAiYWRtaW4ifV0";
    const INVALID_BASE64_DISCLOSURE: &str = "%";
    const INVALID_BASE64_MESSAGE: &str =
        "Error decoding disclosure %: invalid input: Invalid byte 37, offset 0.";
    const INVALID_JSON_DISCLOSURE: &str = "ew";
    const INVALID_JSON_MESSAGE: &str =
        "Error parsing disclosure ew: EOF while parsing an object at line 1 column 1";

    fn owned(disclosures: &[&str]) -> Vec<String> {
        disclosures
            .iter()
            .map(|disclosure| (*disclosure).to_owned())
            .collect()
    }

    fn assert_invalid_disclosure(error: Error, expected_message: &str) {
        assert_eq!(
            error.to_string(),
            format!("invalid disclosure: {expected_message}")
        );
        match error {
            Error::InvalidDisclosure(message) => assert_eq!(message, expected_message),
            other => panic!("expected InvalidDisclosure, got {other:?}"),
        }
    }

    fn assert_contract_violation(error: Error, expected_detail: &str) {
        match error {
            Error::InvalidState(message) => {
                assert!(
                    message.starts_with("Disclosure preprocessing executor contract violation: "),
                    "unexpected contract error: {message}"
                );
                assert!(
                    message.contains(expected_detail),
                    "expected `{expected_detail}` in `{message}`"
                );
            }
            other => panic!("expected InvalidState, got {other:?}"),
        }
    }

    #[test]
    fn worker_preserves_identity_and_computes_exact_value_and_hash() {
        let disclosures = owned(&[OBJECT_DISCLOSURE]);
        let jobs = plan_disclosures(&disclosures);

        let outcome = process_disclosure(&jobs[0]);

        assert_eq!(outcome.ordinal, 0);
        assert_eq!(outcome.encoded_disclosure, OBJECT_DISCLOSURE);
        let processed = outcome.result.unwrap();
        assert_eq!(processed.digest, OBJECT_DISCLOSURE_HASH);
        assert_eq!(
            processed.decoded_disclosure,
            json!(["salt", "name", { "role": "admin" }])
        );
    }

    #[test]
    fn serial_executor_returns_one_identity_bound_outcome_per_job() {
        let disclosures = owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE, WHITESPACE_DISCLOSURE]);
        let jobs = plan_disclosures(&disclosures);

        let outcomes = SerialDisclosureExecutor.execute(&jobs);

        assert_eq!(outcomes.len(), jobs.len());
        for (job, outcome) in jobs.iter().zip(&outcomes) {
            assert_eq!(outcome.ordinal, job.ordinal);
            assert_eq!(outcome.encoded_disclosure, job.encoded_disclosure);
        }
    }

    #[test]
    fn assembler_restores_shuffled_outcomes_before_building_mappings() {
        let disclosures = owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE, WHITESPACE_DISCLOSURE]);
        let jobs = plan_disclosures(&disclosures);
        let mut outcomes = SerialDisclosureExecutor.execute(&jobs);
        outcomes.swap(0, 2);

        let mappings = assemble_disclosures(&jobs, outcomes).unwrap();

        assert_eq!(mappings.hash_to_decoded_disclosure.len(), 3);
        assert_eq!(mappings.hash_to_disclosure.len(), 3);
        assert_eq!(
            mappings
                .hash_to_disclosure
                .get(OBJECT_DISCLOSURE_HASH)
                .map(String::as_str),
            Some(OBJECT_DISCLOSURE)
        );
        assert_eq!(
            mappings
                .hash_to_disclosure
                .get(ARRAY_DISCLOSURE_HASH)
                .map(String::as_str),
            Some(ARRAY_DISCLOSURE)
        );
    }

    #[test]
    fn assembler_uses_lowest_ordinal_malformed_error_after_shuffle() {
        let disclosures = owned(&[INVALID_JSON_DISCLOSURE, INVALID_BASE64_DISCLOSURE]);
        let jobs = plan_disclosures(&disclosures);
        let mut outcomes = SerialDisclosureExecutor.execute(&jobs);
        outcomes.reverse();

        let error = assemble_disclosures(&jobs, outcomes).unwrap_err();

        assert_invalid_disclosure(error, INVALID_JSON_MESSAGE);
    }

    #[test]
    fn assembler_keeps_malformed_error_before_later_duplicate_after_shuffle() {
        let disclosures = owned(&[
            INVALID_JSON_DISCLOSURE,
            OBJECT_DISCLOSURE,
            OBJECT_DISCLOSURE,
        ]);
        let jobs = plan_disclosures(&disclosures);
        let mut outcomes = SerialDisclosureExecutor.execute(&jobs);
        outcomes.reverse();

        let error = assemble_disclosures(&jobs, outcomes).unwrap_err();

        assert_invalid_disclosure(error, INVALID_JSON_MESSAGE);
    }

    #[test]
    fn assembler_preserves_duplicate_disclosure_precedence_after_shuffle() {
        let disclosures = owned(&[
            OBJECT_DISCLOSURE,
            OBJECT_DISCLOSURE,
            INVALID_JSON_DISCLOSURE,
        ]);
        let jobs = plan_disclosures(&disclosures);
        let mut outcomes = SerialDisclosureExecutor.execute(&jobs);
        outcomes.reverse();

        let error = assemble_disclosures(&jobs, outcomes).unwrap_err();

        match error {
            Error::DuplicateDigestError(digest) => {
                assert_eq!(digest, OBJECT_DISCLOSURE_HASH)
            }
            other => panic!("expected DuplicateDigestError, got {other:?}"),
        }
    }

    #[test]
    fn assembler_rejects_missing_outcome() {
        let disclosures = owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]);
        let jobs = plan_disclosures(&disclosures);
        let mut outcomes = SerialDisclosureExecutor.execute(&jobs);
        outcomes.remove(1);

        let error = assemble_disclosures(&jobs, outcomes).unwrap_err();

        assert_contract_violation(error, "no outcome was returned for ordinal 1");
    }

    #[test]
    fn assembler_rejects_duplicate_outcome() {
        let disclosures = owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]);
        let jobs = plan_disclosures(&disclosures);
        let mut outcomes = SerialDisclosureExecutor.execute(&jobs);
        outcomes.push(process_disclosure(&jobs[1]));

        let error = assemble_disclosures(&jobs, outcomes).unwrap_err();

        assert_contract_violation(error, "multiple outcomes were returned for ordinal 1");
    }

    #[test]
    fn assembler_rejects_out_of_range_outcome() {
        let disclosures = owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]);
        let jobs = plan_disclosures(&disclosures);
        let mut outcomes = SerialDisclosureExecutor.execute(&jobs);
        outcomes[1].ordinal = jobs.len();

        let error = assemble_disclosures(&jobs, outcomes).unwrap_err();

        assert_contract_violation(error, "outcome ordinal 2 is out of range for 2 jobs");
    }

    #[test]
    fn assembler_rejects_identity_mutation() {
        let disclosures = owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]);
        let jobs = plan_disclosures(&disclosures);
        let mut outcomes = SerialDisclosureExecutor.execute(&jobs);
        outcomes[1].encoded_disclosure = jobs[0].encoded_disclosure;

        let error = assemble_disclosures(&jobs, outcomes).unwrap_err();

        assert_contract_violation(error, "encoded identity changed for ordinal 1");
    }

    #[test]
    fn worker_preserves_legacy_malformed_disclosure_errors() {
        for (disclosure, expected_message) in [
            (INVALID_BASE64_DISCLOSURE, INVALID_BASE64_MESSAGE),
            (INVALID_JSON_DISCLOSURE, INVALID_JSON_MESSAGE),
        ] {
            let disclosures = owned(&[disclosure]);
            let jobs = plan_disclosures(&disclosures);
            let outcome = process_disclosure(&jobs[0]);

            assert_invalid_disclosure(outcome.result.unwrap_err(), expected_message);
        }
    }
}
