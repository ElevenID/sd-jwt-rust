// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use crate::utils::{base64_hash, base64url_decode};
use serde_json::Value;
use std::collections::HashMap;
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
use std::thread;

// Provisional opt-in policy. These cutoffs deliberately favor the serial
// oracle until benchmarks cover the target architecture and payload mix.
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
const PARALLEL_MIN_DISCLOSURES: usize = 128;
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
const PARALLEL_MIN_TOTAL_ENCODED_BYTES: usize = 1024 * 1024;
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
const MAX_PARALLEL_WORKERS: usize = 4;
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
const PARALLEL_WORKER_FAILURE: &str = "Disclosure preprocessing executor failure: worker panicked";
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
const PARALLEL_SPAWN_FAILURE: &str =
    "Disclosure preprocessing executor failure: could not spawn worker";

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
    fn execute<'a>(&self, jobs: &[DisclosureJob<'a>]) -> Result<Vec<DisclosureOutcome<'a>>>;
}

/// The behavioral oracle and the fallback when native parallel execution is
/// unavailable or below its measured workload threshold.
struct SerialDisclosureExecutor;

impl DisclosureExecutor for SerialDisclosureExecutor {
    fn execute<'a>(&self, jobs: &[DisclosureJob<'a>]) -> Result<Vec<DisclosureOutcome<'a>>> {
        Ok(jobs.iter().map(process_disclosure).collect())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DisclosureExecutionMode {
    Serial,
    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    NativeParallel {
        worker_count: usize,
    },
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
type DisclosureWorker = for<'a> fn(&DisclosureJob<'a>) -> DisclosureOutcome<'a>;

/// A bounded native executor. It divides the immutable job slice into at most
/// `MAX_PARALLEL_WORKERS` chunks and uses scoped threads so disclosures do not
/// need to be copied or given a `'static` lifetime.
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
struct NativeParallelDisclosureExecutor {
    worker_count: usize,
    worker: DisclosureWorker,
    #[cfg(test)]
    forced_spawn_failure_at: Option<usize>,
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
impl NativeParallelDisclosureExecutor {
    fn new(worker_count: usize) -> Self {
        Self {
            worker_count: worker_count.clamp(1, MAX_PARALLEL_WORKERS),
            worker: process_disclosure,
            #[cfg(test)]
            forced_spawn_failure_at: None,
        }
    }

    #[cfg(test)]
    fn with_worker(worker_count: usize, worker: DisclosureWorker) -> Self {
        Self {
            worker_count: worker_count.clamp(1, MAX_PARALLEL_WORKERS),
            worker,
            forced_spawn_failure_at: None,
        }
    }

    #[cfg(test)]
    fn with_forced_spawn_failure(worker_count: usize, spawn_index: usize) -> Self {
        Self {
            worker_count: worker_count.clamp(1, MAX_PARALLEL_WORKERS),
            worker: process_disclosure,
            forced_spawn_failure_at: Some(spawn_index),
        }
    }
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
fn static_chunk_size(job_count: usize, worker_count: usize) -> usize {
    debug_assert!(job_count > 0);
    debug_assert!(worker_count > 0);
    job_count / worker_count + usize::from(job_count % worker_count != 0)
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
impl DisclosureExecutor for NativeParallelDisclosureExecutor {
    fn execute<'a>(&self, jobs: &[DisclosureJob<'a>]) -> Result<Vec<DisclosureOutcome<'a>>> {
        if jobs.is_empty() {
            return Ok(Vec::new());
        }

        let worker_count = self.worker_count.min(jobs.len());
        let chunk_size = static_chunk_size(jobs.len(), worker_count);
        let worker = self.worker;

        thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            let mut spawn_failed = false;

            for chunk in jobs.chunks(chunk_size) {
                #[cfg(test)]
                if self.forced_spawn_failure_at == Some(handles.len()) {
                    spawn_failed = true;
                    break;
                }

                let handle = thread::Builder::new()
                    .name("sd-jwt-disclosure-worker".to_owned())
                    .spawn_scoped(scope, move || chunk.iter().map(worker).collect::<Vec<_>>());
                match handle {
                    Ok(handle) => handles.push(handle),
                    Err(_) => {
                        spawn_failed = true;
                        break;
                    }
                }
            }

            let mut outcomes = Vec::with_capacity(jobs.len());
            let mut worker_panicked = false;
            for handle in handles {
                match handle.join() {
                    Ok(mut chunk_outcomes) => outcomes.append(&mut chunk_outcomes),
                    Err(_) => worker_panicked = true,
                }
            }

            if spawn_failed {
                Err(Error::InvalidState(PARALLEL_SPAWN_FAILURE.to_owned()))
            } else if worker_panicked {
                Err(Error::InvalidState(PARALLEL_WORKER_FAILURE.to_owned()))
            } else {
                Ok(outcomes)
            }
        })
    }
}

#[derive(Debug, PartialEq)]
pub(super) struct DisclosureMappings {
    pub(super) hash_to_decoded_disclosure: HashMap<String, Value>,
    pub(super) hash_to_disclosure: HashMap<String, String>,
    pub(super) ordered_disclosure_digests: Vec<String>,
}

pub(super) fn preprocess_disclosures(encoded_disclosures: &[String]) -> Result<DisclosureMappings> {
    let jobs = plan_disclosures(encoded_disclosures);
    let outcomes = match select_execution_mode(&jobs) {
        DisclosureExecutionMode::Serial => SerialDisclosureExecutor.execute(&jobs),
        #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
        DisclosureExecutionMode::NativeParallel { worker_count } => {
            NativeParallelDisclosureExecutor::new(worker_count).execute(&jobs)
        }
    }?;
    assemble_disclosures(&jobs, outcomes)
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
fn available_worker_threads() -> usize {
    thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(1)
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
fn select_execution_mode(jobs: &[DisclosureJob<'_>]) -> DisclosureExecutionMode {
    select_execution_mode_with_thread_supplier(jobs, available_worker_threads)
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
fn select_execution_mode_with_thread_supplier<F>(
    jobs: &[DisclosureJob<'_>],
    available_threads: F,
) -> DisclosureExecutionMode
where
    F: FnOnce() -> usize,
{
    select_execution_mode_for_lengths_with_thread_supplier(
        jobs.len(),
        jobs.iter().map(|job| job.encoded_disclosure.len()),
        available_threads,
    )
}

#[cfg(all(test, feature = "parallel", target_arch = "x86_64"))]
fn select_execution_mode_for_lengths<I>(
    disclosure_count: usize,
    encoded_lengths: I,
    available_threads: usize,
) -> DisclosureExecutionMode
where
    I: Clone + IntoIterator<Item = usize>,
{
    select_execution_mode_for_lengths_with_thread_supplier(
        disclosure_count,
        encoded_lengths,
        || available_threads,
    )
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
fn select_execution_mode_for_lengths_with_thread_supplier<I, F>(
    disclosure_count: usize,
    encoded_lengths: I,
    available_threads: F,
) -> DisclosureExecutionMode
where
    I: Clone + IntoIterator<Item = usize>,
    F: FnOnce() -> usize,
{
    if disclosure_count < PARALLEL_MIN_DISCLOSURES {
        return DisclosureExecutionMode::Serial;
    }

    let mut observed_count = 0usize;
    let mut total_encoded_bytes = 0u128;

    for encoded_length in encoded_lengths.clone() {
        if observed_count == disclosure_count {
            return DisclosureExecutionMode::Serial;
        }

        let encoded_length = encoded_length as u128;
        total_encoded_bytes = total_encoded_bytes.saturating_add(encoded_length);
        observed_count += 1;
    }

    if observed_count != disclosure_count {
        return DisclosureExecutionMode::Serial;
    }

    if total_encoded_bytes < PARALLEL_MIN_TOTAL_ENCODED_BYTES as u128 {
        return DisclosureExecutionMode::Serial;
    }

    let available_threads = available_threads();
    if available_threads <= 1 {
        return DisclosureExecutionMode::Serial;
    }

    let worker_count = available_threads
        .min(disclosure_count)
        .min(MAX_PARALLEL_WORKERS);
    let chunk_size = static_chunk_size(disclosure_count, worker_count);
    let mut observed_count = 0usize;
    let mut current_chunk_bytes = 0u128;
    let mut largest_chunk_bytes = 0u128;

    for encoded_length in encoded_lengths {
        current_chunk_bytes = current_chunk_bytes.saturating_add(encoded_length as u128);
        observed_count += 1;

        if observed_count % chunk_size == 0 {
            largest_chunk_bytes = largest_chunk_bytes.max(current_chunk_bytes);
            current_chunk_bytes = 0;
        }
    }
    largest_chunk_bytes = largest_chunk_bytes.max(current_chunk_bytes);

    // Match the executor's contiguous count-based chunks. Requiring the
    // largest chunk to hold at most half the encoded bytes allows an even
    // two-worker split while rejecting one-dominant and clustered workloads.
    let half_total_rounded_up = total_encoded_bytes / 2 + total_encoded_bytes % 2;
    if largest_chunk_bytes > half_total_rounded_up {
        return DisclosureExecutionMode::Serial;
    }

    DisclosureExecutionMode::NativeParallel { worker_count }
}

#[cfg(not(all(feature = "parallel", target_arch = "x86_64")))]
fn select_execution_mode(_jobs: &[DisclosureJob<'_>]) -> DisclosureExecutionMode {
    DisclosureExecutionMode::Serial
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
    let mut ordered_disclosure_digests = Vec::with_capacity(jobs.len());

    for outcome in outcomes {
        let processed = outcome.result?;
        if hash_to_decoded_disclosure.contains_key(&processed.digest) {
            return Err(Error::DuplicateDigestError(processed.digest));
        }

        hash_to_disclosure.insert(
            processed.digest.clone(),
            outcome.encoded_disclosure.to_owned(),
        );
        ordered_disclosure_digests.push(processed.digest.clone());
        hash_to_decoded_disclosure.insert(processed.digest, processed.decoded_disclosure);
    }

    Ok(DisclosureMappings {
        hash_to_decoded_disclosure,
        hash_to_disclosure,
        ordered_disclosure_digests,
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
    const WHITESPACE_DISCLOSURE_HASH: &str = "heY8-8zXVWlYO5sT5PWM6IQGEGJcyW_aTHm-2D1DgTQ";
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

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    fn balanced_lengths(disclosure_count: usize, total_encoded_bytes: usize) -> Vec<usize> {
        let bytes_per_disclosure = total_encoded_bytes / disclosure_count;
        let remainder = total_encoded_bytes % disclosure_count;

        (0..disclosure_count)
            .map(|ordinal| bytes_per_disclosure + usize::from(ordinal < remainder))
            .collect()
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    fn mode_for_lengths(
        encoded_lengths: &[usize],
        available_threads: usize,
    ) -> DisclosureExecutionMode {
        select_execution_mode_for_lengths(
            encoded_lengths.len(),
            encoded_lengths.iter().copied(),
            available_threads,
        )
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

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    fn generated_disclosures(count: usize, value_size: usize) -> Vec<String> {
        (0..count)
            .map(|ordinal| {
                let decoded = serde_json::to_vec(&json!([
                    format!("salt-{ordinal}"),
                    format!("claim-{ordinal}"),
                    "x".repeat(value_size)
                ]))
                .unwrap();
                crate::utils::base64url_encode(&decoded)
            })
            .collect()
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    fn deterministic_shuffle<T>(values: &mut [T]) {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for upper in (1..values.len()).rev() {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            values.swap(upper, (state as usize) % (upper + 1));
        }
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    fn error_signature(error: Error) -> (String, String) {
        (format!("{error:?}"), error.to_string())
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    fn assert_parallel_executor_failure(error: Error, expected_message: &str) {
        assert_eq!(
            error.to_string(),
            format!("invalid state: {expected_message}")
        );
        match error {
            Error::InvalidState(message) => {
                assert_eq!(message, expected_message);
                assert!(!message.contains("ordinal"));
                assert!(!message.contains(OBJECT_DISCLOSURE));
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

        let outcomes = SerialDisclosureExecutor.execute(&jobs).unwrap();

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
        let mut outcomes = SerialDisclosureExecutor.execute(&jobs).unwrap();
        outcomes.swap(0, 2);

        let mappings = assemble_disclosures(&jobs, outcomes).unwrap();

        assert_eq!(mappings.hash_to_decoded_disclosure.len(), 3);
        assert_eq!(mappings.hash_to_disclosure.len(), 3);
        assert_eq!(
            mappings.ordered_disclosure_digests,
            [
                OBJECT_DISCLOSURE_HASH,
                ARRAY_DISCLOSURE_HASH,
                WHITESPACE_DISCLOSURE_HASH,
            ]
        );
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
        let mut outcomes = SerialDisclosureExecutor.execute(&jobs).unwrap();
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
        let mut outcomes = SerialDisclosureExecutor.execute(&jobs).unwrap();
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
        let mut outcomes = SerialDisclosureExecutor.execute(&jobs).unwrap();
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
        let mut outcomes = SerialDisclosureExecutor.execute(&jobs).unwrap();
        outcomes.remove(1);

        let error = assemble_disclosures(&jobs, outcomes).unwrap_err();

        assert_contract_violation(error, "no outcome was returned for ordinal 1");
    }

    #[test]
    fn assembler_rejects_duplicate_outcome() {
        let disclosures = owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]);
        let jobs = plan_disclosures(&disclosures);
        let mut outcomes = SerialDisclosureExecutor.execute(&jobs).unwrap();
        outcomes.push(process_disclosure(&jobs[1]));

        let error = assemble_disclosures(&jobs, outcomes).unwrap_err();

        assert_contract_violation(error, "multiple outcomes were returned for ordinal 1");
    }

    #[test]
    fn assembler_rejects_out_of_range_outcome() {
        let disclosures = owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]);
        let jobs = plan_disclosures(&disclosures);
        let mut outcomes = SerialDisclosureExecutor.execute(&jobs).unwrap();
        outcomes[1].ordinal = jobs.len();

        let error = assemble_disclosures(&jobs, outcomes).unwrap_err();

        assert_contract_violation(error, "outcome ordinal 2 is out of range for 2 jobs");
    }

    #[test]
    fn assembler_rejects_identity_mutation() {
        let disclosures = owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]);
        let jobs = plan_disclosures(&disclosures);
        let mut outcomes = SerialDisclosureExecutor.execute(&jobs).unwrap();
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

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn native_parallel_matches_serial_after_deterministic_completion_shuffle() {
        let disclosures = generated_disclosures(64, 512);
        let jobs = plan_disclosures(&disclosures);
        let serial_outcomes = SerialDisclosureExecutor.execute(&jobs).unwrap();
        let serial_mappings = assemble_disclosures(&jobs, serial_outcomes).unwrap();

        let mut parallel_outcomes = NativeParallelDisclosureExecutor::new(4)
            .execute(&jobs)
            .unwrap();
        deterministic_shuffle(&mut parallel_outcomes);
        let parallel_mappings = assemble_disclosures(&jobs, parallel_outcomes).unwrap();

        assert_eq!(parallel_mappings, serial_mappings);
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn native_parallel_matches_serial_error_variant_message_and_precedence() {
        for disclosures in [
            owned(&[INVALID_JSON_DISCLOSURE, INVALID_BASE64_DISCLOSURE]),
            owned(&[
                INVALID_JSON_DISCLOSURE,
                OBJECT_DISCLOSURE,
                OBJECT_DISCLOSURE,
            ]),
            owned(&[
                OBJECT_DISCLOSURE,
                OBJECT_DISCLOSURE,
                INVALID_JSON_DISCLOSURE,
            ]),
        ] {
            let jobs = plan_disclosures(&disclosures);
            let serial_error =
                assemble_disclosures(&jobs, SerialDisclosureExecutor.execute(&jobs).unwrap())
                    .unwrap_err();
            let mut parallel_outcomes = NativeParallelDisclosureExecutor::new(3)
                .execute(&jobs)
                .unwrap();
            parallel_outcomes.reverse();
            let parallel_error = assemble_disclosures(&jobs, parallel_outcomes).unwrap_err();

            assert_eq!(
                error_signature(parallel_error),
                error_signature(serial_error)
            );
        }
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn native_parallel_fails_closed_on_worker_panic_without_item_data() {
        fn panicking_worker<'a>(job: &DisclosureJob<'a>) -> DisclosureOutcome<'a> {
            if job.ordinal == 1 {
                panic!("injected worker failure");
            }
            process_disclosure(job)
        }

        let disclosures = generated_disclosures(8, 64);
        let jobs = plan_disclosures(&disclosures);

        let error = NativeParallelDisclosureExecutor::with_worker(2, panicking_worker)
            .execute(&jobs)
            .unwrap_err();

        assert_parallel_executor_failure(error, PARALLEL_WORKER_FAILURE);
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn native_parallel_fails_closed_on_spawn_failure_without_item_data() {
        let disclosures = generated_disclosures(8, 64);
        let jobs = plan_disclosures(&disclosures);

        let error = NativeParallelDisclosureExecutor::with_forced_spawn_failure(2, 1)
            .execute(&jobs)
            .unwrap_err();

        assert_parallel_executor_failure(error, PARALLEL_SPAWN_FAILURE);
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn adaptive_policy_uses_documented_cutoffs_and_bounds_workers() {
        let below_count = balanced_lengths(
            PARALLEL_MIN_DISCLOSURES - 1,
            PARALLEL_MIN_TOTAL_ENCODED_BYTES,
        );
        assert_eq!(
            mode_for_lengths(&below_count, MAX_PARALLEL_WORKERS),
            DisclosureExecutionMode::Serial
        );

        let below_bytes = balanced_lengths(
            PARALLEL_MIN_DISCLOSURES,
            PARALLEL_MIN_TOTAL_ENCODED_BYTES - 1,
        );
        assert_eq!(
            mode_for_lengths(&below_bytes, MAX_PARALLEL_WORKERS),
            DisclosureExecutionMode::Serial
        );

        let at_cutoffs =
            balanced_lengths(PARALLEL_MIN_DISCLOSURES, PARALLEL_MIN_TOTAL_ENCODED_BYTES);
        assert_eq!(
            mode_for_lengths(&at_cutoffs, 1),
            DisclosureExecutionMode::Serial
        );
        assert_eq!(
            mode_for_lengths(&at_cutoffs, usize::MAX),
            DisclosureExecutionMode::NativeParallel {
                worker_count: MAX_PARALLEL_WORKERS,
            }
        );
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn adaptive_policy_skips_thread_query_until_cheap_gates_pass() {
        use std::cell::Cell;

        let thread_query_count = Cell::new(0usize);
        let select = |encoded_lengths: &[usize]| {
            select_execution_mode_for_lengths_with_thread_supplier(
                encoded_lengths.len(),
                encoded_lengths.iter().copied(),
                || {
                    thread_query_count.set(thread_query_count.get() + 1);
                    MAX_PARALLEL_WORKERS
                },
            )
        };

        let below_count = balanced_lengths(
            PARALLEL_MIN_DISCLOSURES - 1,
            PARALLEL_MIN_TOTAL_ENCODED_BYTES,
        );
        assert_eq!(select(&below_count), DisclosureExecutionMode::Serial);
        assert_eq!(thread_query_count.get(), 0);

        let below_bytes = balanced_lengths(
            PARALLEL_MIN_DISCLOSURES,
            PARALLEL_MIN_TOTAL_ENCODED_BYTES - 1,
        );
        assert_eq!(select(&below_bytes), DisclosureExecutionMode::Serial);
        assert_eq!(thread_query_count.get(), 0);

        let eligible = balanced_lengths(PARALLEL_MIN_DISCLOSURES, PARALLEL_MIN_TOTAL_ENCODED_BYTES);
        assert_eq!(
            select(&eligible),
            DisclosureExecutionMode::NativeParallel {
                worker_count: MAX_PARALLEL_WORKERS,
            }
        );
        assert_eq!(thread_query_count.get(), 1);
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn adaptive_policy_rejects_imbalanced_static_chunks() {
        let balanced_large = vec![64 * 1024; PARALLEL_MIN_DISCLOSURES];
        assert_eq!(
            mode_for_lengths(&balanced_large, MAX_PARALLEL_WORKERS),
            DisclosureExecutionMode::NativeParallel {
                worker_count: MAX_PARALLEL_WORKERS,
            }
        );

        let balanced_mixed: Vec<_> = (0..PARALLEL_MIN_DISCLOSURES)
            .map(|ordinal| match ordinal % 4 {
                0 => 64,
                1 => 1024,
                _ => 64 * 1024,
            })
            .collect();
        assert_eq!(
            mode_for_lengths(&balanced_mixed, MAX_PARALLEL_WORKERS),
            DisclosureExecutionMode::NativeParallel {
                worker_count: MAX_PARALLEL_WORKERS,
            }
        );

        let mut one_dominant = vec![1; PARALLEL_MIN_DISCLOSURES];
        one_dominant[0] = PARALLEL_MIN_TOTAL_ENCODED_BYTES;
        assert_eq!(
            mode_for_lengths(&one_dominant, MAX_PARALLEL_WORKERS),
            DisclosureExecutionMode::Serial
        );

        let mut clustered = vec![1; PARALLEL_MIN_DISCLOSURES];
        let first_chunk_len = static_chunk_size(PARALLEL_MIN_DISCLOSURES, MAX_PARALLEL_WORKERS);
        clustered[..first_chunk_len].fill(64 * 1024);
        assert_eq!(
            mode_for_lengths(&clustered, MAX_PARALLEL_WORKERS),
            DisclosureExecutionMode::Serial
        );
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn adaptive_policy_byte_accounting_does_not_overflow() {
        let maximal_lengths = vec![usize::MAX; PARALLEL_MIN_DISCLOSURES];

        assert_eq!(
            mode_for_lengths(&maximal_lengths, MAX_PARALLEL_WORKERS),
            DisclosureExecutionMode::NativeParallel {
                worker_count: MAX_PARALLEL_WORKERS,
            }
        );
    }

    #[cfg(not(feature = "parallel"))]
    #[test]
    fn feature_off_always_selects_serial_execution() {
        let disclosures = owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]);
        let jobs = plan_disclosures(&disclosures);

        assert_eq!(
            select_execution_mode(&jobs),
            DisclosureExecutionMode::Serial
        );
    }

    #[cfg(all(feature = "parallel", not(target_arch = "x86_64")))]
    #[test]
    fn unmeasured_architecture_parallel_feature_still_selects_serial_execution() {
        let disclosures = owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]);
        let jobs = plan_disclosures(&disclosures);

        assert_eq!(
            select_execution_mode(&jobs),
            DisclosureExecutionMode::Serial
        );
    }
}
