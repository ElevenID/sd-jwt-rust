// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use crate::utils::{base64_hash, base64url_decode};
use serde_json::Value;
use std::collections::HashMap;
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
use std::thread;

// Provisional opt-in policy. These cutoffs deliberately favor the serial
// oracle until benchmarks cover the target architecture and payload mix.
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
const PARALLEL_MIN_DISCLOSURES: usize = 128;
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
const PARALLEL_MIN_TOTAL_ENCODED_BYTES: usize = 1024 * 1024;
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
pub(crate) const MAX_PARALLEL_WORKERS: usize = 4;
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
pub(crate) struct DisclosureJob<'a> {
    pub(crate) ordinal: usize,
    pub(crate) encoded_disclosure: &'a str,
}

#[derive(Debug)]
pub(crate) struct ProcessedDisclosure {
    pub(crate) digest: String,
    pub(crate) decoded_disclosure: Value,
}

/// A worker outcome retains identity even when decoding or parsing fails.
/// A missing result is reserved for executor-contract validation.
#[derive(Debug)]
pub(crate) struct DisclosureOutcome<'a> {
    pub(crate) ordinal: usize,
    pub(crate) encoded_disclosure: &'a str,
    pub(crate) result: Option<Result<ProcessedDisclosure>>,
}

type DisclosureWorker = for<'a> fn(&DisclosureJob<'a>) -> DisclosureOutcome<'a>;

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
trait DisclosureExecutor {
    fn execute<'a>(&self, jobs: &[DisclosureJob<'a>]) -> Result<Vec<DisclosureOutcome<'a>>>;
}

/// The behavioral oracle and the fallback when native parallel execution is
/// unavailable or below its measured workload threshold.
struct SerialDisclosureExecutor;

impl SerialDisclosureExecutor {
    /// Process and assemble disclosures incrementally so the default and
    /// fallback paths retain the legacy fail-fast resource behavior. No
    /// attacker-controlled tail is planned, padded, sorted, or preallocated
    /// after an earlier malformed or duplicate disclosure.
    fn preprocess(encoded_disclosures: &[String]) -> Result<DisclosureMappings> {
        Self::preprocess_with_worker(encoded_disclosures, process_disclosure)
    }

    fn preprocess_with_worker(
        encoded_disclosures: &[String],
        worker: DisclosureWorker,
    ) -> Result<DisclosureMappings> {
        let mut hash_to_decoded_disclosure = HashMap::new();
        let mut hash_to_disclosure = HashMap::new();
        let mut ordered_disclosure_digests = Vec::new();

        for (ordinal, encoded_disclosure) in encoded_disclosures.iter().enumerate() {
            let job = DisclosureJob {
                ordinal,
                encoded_disclosure,
            };
            let outcome = worker(&job);

            if outcome.ordinal != ordinal {
                return Err(executor_contract_error(format!(
                    "outcome ordinal {} does not match planned ordinal {ordinal}",
                    outcome.ordinal
                )));
            }
            if outcome.encoded_disclosure != encoded_disclosure {
                return Err(executor_contract_error(format!(
                    "encoded identity changed for ordinal {ordinal}"
                )));
            }

            let processed = match outcome.result {
                Some(result) => result?,
                None => {
                    return Err(executor_contract_error(format!(
                        "no preprocessing result was returned for ordinal {ordinal}"
                    )))
                }
            };
            if hash_to_decoded_disclosure.contains_key(&processed.digest) {
                return Err(Error::DuplicateDigestError(processed.digest));
            }

            hash_to_disclosure.insert(processed.digest.clone(), encoded_disclosure.to_owned());
            ordered_disclosure_digests.push(processed.digest.clone());
            hash_to_decoded_disclosure.insert(processed.digest, processed.decoded_disclosure);
        }

        Ok(DisclosureMappings {
            hash_to_decoded_disclosure,
            hash_to_disclosure,
            ordered_disclosure_digests,
        })
    }

    #[cfg(test)]
    fn execute_with_worker<'a>(
        jobs: &[DisclosureJob<'a>],
        worker: DisclosureWorker,
    ) -> Result<Vec<DisclosureOutcome<'a>>> {
        let mut outcomes = Vec::new();

        for job in jobs {
            let outcome = worker(job);
            match outcome {
                DisclosureOutcome {
                    result: Some(Err(error)),
                    ..
                } => return Err(error),
                DisclosureOutcome {
                    ordinal,
                    result: None,
                    ..
                } => {
                    return Err(executor_contract_error(format!(
                        "no preprocessing result was returned for ordinal {ordinal}"
                    )))
                }
                outcome => outcomes.push(outcome),
            }
        }

        Ok(outcomes)
    }
}

#[cfg(test)]
impl DisclosureExecutor for SerialDisclosureExecutor {
    fn execute<'a>(&self, jobs: &[DisclosureJob<'a>]) -> Result<Vec<DisclosureOutcome<'a>>> {
        Self::execute_with_worker(jobs, process_disclosure)
    }
}

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DisclosureExecutionMode {
    Serial,
    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    NativeParallel {
        worker_count: usize,
    },
}

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

/// A non-blocking, process-wide cap on OS threads spawned by disclosure
/// preprocessing. When an exact lease is unavailable, the request uses the
/// serial oracle instead of waiting or changing the measured chunk layout.
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
pub(crate) struct ParallelWorkerBudget {
    available: AtomicUsize,
    capacity: usize,
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
impl ParallelWorkerBudget {
    const fn new(capacity: usize) -> Self {
        Self {
            available: AtomicUsize::new(capacity),
            capacity,
        }
    }

    pub(crate) fn try_acquire(&self, worker_count: usize) -> Option<ParallelWorkerLease<'_>> {
        if worker_count < 2 || worker_count > self.capacity {
            return None;
        }

        let mut available = self.available.load(Ordering::Acquire);
        loop {
            if available < worker_count {
                return None;
            }

            match self.available.compare_exchange_weak(
                available,
                available - worker_count,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ParallelWorkerLease {
                        budget: self,
                        worker_count,
                    })
                }
                Err(observed) => available = observed,
            }
        }
    }

    #[cfg(test)]
    fn available(&self) -> usize {
        self.available.load(Ordering::Acquire)
    }
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
pub(crate) struct ParallelWorkerLease<'a> {
    budget: &'a ParallelWorkerBudget,
    worker_count: usize,
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
impl ParallelWorkerLease<'_> {
    pub(crate) fn worker_count(&self) -> usize {
        self.worker_count
    }
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
impl Drop for ParallelWorkerLease<'_> {
    fn drop(&mut self) {
        let previously_available = self
            .budget
            .available
            .fetch_add(self.worker_count, Ordering::Release);
        debug_assert!(
            previously_available <= self.budget.capacity - self.worker_count,
            "parallel worker budget over-release"
        );
    }
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
static PARALLEL_WORKER_BUDGET: ParallelWorkerBudget =
    ParallelWorkerBudget::new(MAX_PARALLEL_WORKERS);

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
pub(crate) fn process_wide_disclosure_worker_budget() -> &'static ParallelWorkerBudget {
    &PARALLEL_WORKER_BUDGET
}

#[cfg(all(test, feature = "parallel", target_arch = "x86_64"))]
std::thread_local! {
    static POLICY_TOTAL_SCAN_COUNT: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
    static POLICY_BALANCE_SCAN_COUNT: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
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

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
fn execute_parallel_with_lease<'a>(
    jobs: &[DisclosureJob<'a>],
    lease: ParallelWorkerLease<'_>,
) -> Result<Vec<DisclosureOutcome<'a>>> {
    let outcomes = NativeParallelDisclosureExecutor::new(lease.worker_count()).execute(jobs);
    // Every scoped worker has joined when `execute` returns. Release the
    // process-wide thread permits before deterministic serial assembly.
    drop(lease);
    outcomes
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
fn preprocess_parallel_with_lease(
    encoded_disclosures: &[String],
    lease: ParallelWorkerLease<'_>,
) -> Result<DisclosureMappings> {
    let jobs = plan_disclosures(encoded_disclosures);
    let outcomes = execute_parallel_with_lease(&jobs, lease)?;
    assemble_disclosures(&jobs, outcomes)
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
fn preprocess_disclosures_with_budget_and_thread_supplier<F>(
    encoded_disclosures: &[String],
    budget: &ParallelWorkerBudget,
    available_threads: F,
) -> Result<DisclosureMappings>
where
    F: FnOnce() -> usize,
{
    if encoded_disclosures.len() < PARALLEL_MIN_DISCLOSURES {
        return SerialDisclosureExecutor::preprocess(encoded_disclosures);
    }

    #[cfg(test)]
    POLICY_TOTAL_SCAN_COUNT.with(|count| count.set(count.get() + 1));
    let total_encoded_bytes = match eligible_total_encoded_bytes(
        encoded_disclosures.len(),
        encoded_disclosures
            .iter()
            .map(|encoded_disclosure| encoded_disclosure.len()),
    ) {
        Some(total_encoded_bytes) => total_encoded_bytes,
        None => return SerialDisclosureExecutor::preprocess(encoded_disclosures),
    };

    let available_threads = available_threads();
    let worker_count = match bounded_worker_count(encoded_disclosures.len(), available_threads) {
        Some(worker_count) => worker_count,
        None => return SerialDisclosureExecutor::preprocess(encoded_disclosures),
    };

    // Acquire the exact measured worker layout before scanning aggregate
    // balance. A contended request therefore skips the second length pass and
    // reaches the serial fail-fast path without reserving outcome storage.
    let lease = match budget.try_acquire(worker_count) {
        Some(lease) => lease,
        None => return SerialDisclosureExecutor::preprocess(encoded_disclosures),
    };

    #[cfg(test)]
    POLICY_BALANCE_SCAN_COUNT.with(|count| count.set(count.get() + 1));
    match select_execution_mode_for_balanced_lengths(
        encoded_disclosures.len(),
        encoded_disclosures
            .iter()
            .map(|encoded_disclosure| encoded_disclosure.len()),
        total_encoded_bytes,
        available_threads,
    ) {
        DisclosureExecutionMode::Serial => {
            drop(lease);
            SerialDisclosureExecutor::preprocess(encoded_disclosures)
        }
        DisclosureExecutionMode::NativeParallel {
            worker_count: selected_worker_count,
        } => {
            debug_assert_eq!(selected_worker_count, lease.worker_count());
            preprocess_parallel_with_lease(encoded_disclosures, lease)
        }
    }
}

#[derive(Debug, PartialEq)]
pub(super) struct DisclosureMappings {
    pub(super) hash_to_decoded_disclosure: HashMap<String, Value>,
    pub(super) hash_to_disclosure: HashMap<String, String>,
    pub(super) ordered_disclosure_digests: Vec<String>,
}

pub(super) fn preprocess_disclosures(encoded_disclosures: &[String]) -> Result<DisclosureMappings> {
    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    {
        preprocess_disclosures_with_budget_and_thread_supplier(
            encoded_disclosures,
            process_wide_disclosure_worker_budget(),
            available_worker_threads,
        )
    }

    #[cfg(not(all(feature = "parallel", target_arch = "x86_64")))]
    {
        SerialDisclosureExecutor::preprocess(encoded_disclosures)
    }
}

pub(super) fn preprocess_disclosures_serial(
    encoded_disclosures: &[String],
) -> Result<DisclosureMappings> {
    SerialDisclosureExecutor::preprocess(encoded_disclosures)
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
fn available_worker_threads() -> usize {
    thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(1)
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

#[cfg(all(test, feature = "parallel", target_arch = "x86_64"))]
fn select_execution_mode_for_lengths_with_thread_supplier<I, F>(
    disclosure_count: usize,
    encoded_lengths: I,
    available_threads: F,
) -> DisclosureExecutionMode
where
    I: Clone + IntoIterator<Item = usize>,
    F: FnOnce() -> usize,
{
    let total_encoded_bytes =
        match eligible_total_encoded_bytes(disclosure_count, encoded_lengths.clone()) {
            Some(total_encoded_bytes) => total_encoded_bytes,
            None => return DisclosureExecutionMode::Serial,
        };

    select_execution_mode_for_balanced_lengths(
        disclosure_count,
        encoded_lengths,
        total_encoded_bytes,
        available_threads(),
    )
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
fn eligible_total_encoded_bytes<I>(disclosure_count: usize, encoded_lengths: I) -> Option<u128>
where
    I: IntoIterator<Item = usize>,
{
    if disclosure_count < PARALLEL_MIN_DISCLOSURES {
        return None;
    }

    let mut observed_count = 0usize;
    let mut total_encoded_bytes = 0u128;
    for encoded_length in encoded_lengths {
        if observed_count == disclosure_count {
            return None;
        }
        total_encoded_bytes = total_encoded_bytes.saturating_add(encoded_length as u128);
        observed_count += 1;
    }

    if observed_count != disclosure_count
        || total_encoded_bytes < PARALLEL_MIN_TOTAL_ENCODED_BYTES as u128
    {
        None
    } else {
        Some(total_encoded_bytes)
    }
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
fn bounded_worker_count(disclosure_count: usize, available_threads: usize) -> Option<usize> {
    let worker_count = available_threads
        .min(disclosure_count)
        .min(MAX_PARALLEL_WORKERS);
    (worker_count > 1).then_some(worker_count)
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
fn select_execution_mode_for_balanced_lengths<I>(
    disclosure_count: usize,
    encoded_lengths: I,
    total_encoded_bytes: u128,
    available_threads: usize,
) -> DisclosureExecutionMode
where
    I: IntoIterator<Item = usize>,
{
    let worker_count = match bounded_worker_count(disclosure_count, available_threads) {
        Some(worker_count) => worker_count,
        None => return DisclosureExecutionMode::Serial,
    };
    let chunk_size = static_chunk_size(disclosure_count, worker_count);
    let mut observed_count = 0usize;
    let mut current_chunk_bytes = 0u128;
    let mut largest_chunk_bytes = 0u128;

    for encoded_length in encoded_lengths {
        if observed_count == disclosure_count {
            return DisclosureExecutionMode::Serial;
        }
        current_chunk_bytes = current_chunk_bytes.saturating_add(encoded_length as u128);
        observed_count += 1;

        if observed_count % chunk_size == 0 {
            largest_chunk_bytes = largest_chunk_bytes.max(current_chunk_bytes);
            current_chunk_bytes = 0;
        }
    }
    if observed_count != disclosure_count {
        return DisclosureExecutionMode::Serial;
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

#[cfg(all(test, not(all(feature = "parallel", target_arch = "x86_64"))))]
fn select_execution_mode(_encoded_disclosures: &[String]) -> DisclosureExecutionMode {
    DisclosureExecutionMode::Serial
}

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
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
pub(crate) fn process_disclosure<'a>(job: &DisclosureJob<'a>) -> DisclosureOutcome<'a> {
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
        result: Some(result),
    }
}

/// Restore worker outcomes to input order, validate the executor contract, and
/// only then publish complete mappings. Any failure discards all partial state.
pub(crate) fn assemble_disclosures<'a>(
    jobs: &[DisclosureJob<'a>],
    mut outcomes: Vec<DisclosureOutcome<'a>>,
) -> Result<DisclosureMappings> {
    outcomes.sort_by_key(|outcome| outcome.ordinal);
    validate_outcome_contract(jobs, &outcomes)?;

    let mut hash_to_decoded_disclosure = HashMap::with_capacity(jobs.len());
    let mut hash_to_disclosure = HashMap::with_capacity(jobs.len());
    let mut ordered_disclosure_digests = Vec::with_capacity(jobs.len());

    for outcome in outcomes {
        let processed = match outcome.result {
            Some(result) => result?,
            None => {
                return Err(executor_contract_error(format!(
                    "no preprocessing result was returned for ordinal {}",
                    outcome.ordinal
                )))
            }
        };
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
    #[derive(Clone, Copy)]
    enum BenchmarkPayloadClass {
        Small,
        Medium,
        Large,
        Mixed,
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    impl BenchmarkPayloadClass {
        fn label(self) -> &'static str {
            match self {
                Self::Small => "small",
                Self::Medium => "medium",
                Self::Large => "large_64_kib",
                Self::Mixed => "mixed",
            }
        }

        fn value(self, ordinal: usize) -> Value {
            match self {
                Self::Small => Value::String(format!("value-{ordinal}")),
                Self::Medium => json!({
                    "ordinal": ordinal,
                    "profile": {
                        "active": ordinal % 2 == 0,
                        "display_name": format!("Credential subject {ordinal}"),
                        "notes": "medium-payload-".repeat(64),
                    },
                    "roles": ["holder", "member", "verified"],
                }),
                Self::Large => {
                    let suffix = format!("-{ordinal}");
                    Value::String(format!("{}{suffix}", "L".repeat(64 * 1024 - suffix.len())))
                }
                Self::Mixed => match ordinal % 3 {
                    0 => Self::Small.value(ordinal),
                    1 => Self::Medium.value(ordinal),
                    _ => Self::Large.value(ordinal),
                },
            }
        }
    }

    /// Reproduce the no-default-feature benchmark disclosure encoding without
    /// generating randomness or signing. Production salts are Base64url
    /// encodings of 16 bytes, so every salt has exactly 22 ASCII characters.
    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    fn benchmark_encoded_lengths(
        disclosure_count: usize,
        payload_class: BenchmarkPayloadClass,
    ) -> Vec<usize> {
        let salt = "A".repeat(22);

        (0..disclosure_count)
            .map(|ordinal| {
                let key = Value::String(format!("claim_{ordinal:04}")).to_string();
                let value = payload_class.value(ordinal).to_string();
                let decoded = format!(r#"["{salt}", {key}, {value}]"#);
                crate::utils::base64url_encode(decoded.as_bytes()).len()
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
        let processed = outcome.result.unwrap().unwrap();
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
    fn serial_preprocessing_skips_large_tail_after_first_malformed_disclosure() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static WORKER_CALLS: AtomicUsize = AtomicUsize::new(0);

        fn counting_worker<'a>(job: &DisclosureJob<'a>) -> DisclosureOutcome<'a> {
            WORKER_CALLS.fetch_add(1, Ordering::SeqCst);
            process_disclosure(job)
        }

        WORKER_CALLS.store(0, Ordering::SeqCst);
        let mut disclosures = Vec::with_capacity(100_001);
        disclosures.push(INVALID_BASE64_DISCLOSURE.to_owned());
        disclosures.extend((0..100_000).map(|_| OBJECT_DISCLOSURE.to_owned()));

        let error = SerialDisclosureExecutor::preprocess_with_worker(&disclosures, counting_worker)
            .unwrap_err();

        assert_eq!(WORKER_CALLS.load(Ordering::SeqCst), 1);
        assert_invalid_disclosure(error, INVALID_BASE64_MESSAGE);
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
        let mut outcomes = jobs.iter().map(process_disclosure).collect::<Vec<_>>();
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
        let mut outcomes = jobs.iter().map(process_disclosure).collect::<Vec<_>>();
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
        let mut outcomes = jobs.iter().map(process_disclosure).collect::<Vec<_>>();
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
    fn assembler_rejects_skipped_result_without_an_earlier_error() {
        let disclosures = owned(&[OBJECT_DISCLOSURE]);
        let jobs = plan_disclosures(&disclosures);
        let mut outcomes = SerialDisclosureExecutor.execute(&jobs).unwrap();
        outcomes[0].result = None;

        let error = assemble_disclosures(&jobs, outcomes).unwrap_err();

        assert_contract_violation(error, "no preprocessing result was returned for ordinal 0");
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

            assert_invalid_disclosure(outcome.result.unwrap().unwrap_err(), expected_message);
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
            let serial_error = SerialDisclosureExecutor::preprocess(&disclosures).unwrap_err();
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
    fn parallel_worker_budget_caps_overlapping_single_and_cross_credential_leases() {
        let budget = ParallelWorkerBudget::new(MAX_PARALLEL_WORKERS);

        let single_credential = budget.try_acquire(3).unwrap();
        assert_eq!(single_credential.worker_count(), 3);
        assert_eq!(budget.available(), 1);
        let cross_credential = budget.try_acquire(2);
        assert!(cross_credential.is_none());
        assert_eq!(budget.available(), 1);
        drop(single_credential);
        assert_eq!(budget.available(), MAX_PARALLEL_WORKERS);

        let cross_credential = budget.try_acquire(2).unwrap();
        let single_credential = budget.try_acquire(2).unwrap();
        assert_eq!(cross_credential.worker_count(), 2);
        assert_eq!(single_credential.worker_count(), 2);
        assert_eq!(budget.available(), 0);
        assert!(budget.try_acquire(2).is_none());

        drop(cross_credential);
        assert_eq!(budget.available(), 2);
        drop(single_credential);
        assert_eq!(budget.available(), MAX_PARALLEL_WORKERS);
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn parallel_worker_lease_is_released_before_serial_assembly() {
        let budget = ParallelWorkerBudget::new(MAX_PARALLEL_WORKERS);
        let lease = budget.try_acquire(MAX_PARALLEL_WORKERS).unwrap();
        let disclosures = generated_disclosures(PARALLEL_MIN_DISCLOSURES, 64);
        let jobs = plan_disclosures(&disclosures);

        let outcomes = execute_parallel_with_lease(&jobs, lease).unwrap();

        assert_eq!(budget.available(), MAX_PARALLEL_WORKERS);
        assert_eq!(
            assemble_disclosures(&jobs, outcomes)
                .unwrap()
                .ordered_disclosure_digests
                .len(),
            disclosures.len()
        );
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn exhausted_parallel_budget_uses_fail_fast_serial_fallback() {
        use std::cell::Cell;

        let budget = ParallelWorkerBudget::new(MAX_PARALLEL_WORKERS);
        let held_lease = budget.try_acquire(MAX_PARALLEL_WORKERS).unwrap();
        let mut disclosures = Vec::with_capacity(100_001);
        disclosures.push(INVALID_BASE64_DISCLOSURE.to_owned());
        disclosures.extend((0..100_000).map(|_| OBJECT_DISCLOSURE.to_owned()));
        let thread_query_count = Cell::new(0usize);
        POLICY_TOTAL_SCAN_COUNT.with(|count| count.set(0));
        POLICY_BALANCE_SCAN_COUNT.with(|count| count.set(0));

        let error =
            preprocess_disclosures_with_budget_and_thread_supplier(&disclosures, &budget, || {
                thread_query_count.set(thread_query_count.get() + 1);
                MAX_PARALLEL_WORKERS
            })
            .unwrap_err();

        assert_eq!(budget.available(), 0);
        assert_eq!(thread_query_count.get(), 1);
        assert_eq!(POLICY_TOTAL_SCAN_COUNT.with(std::cell::Cell::get), 1);
        assert_eq!(POLICY_BALANCE_SCAN_COUNT.with(std::cell::Cell::get), 0);
        assert_invalid_disclosure(error, INVALID_BASE64_MESSAGE);

        drop(held_lease);
        assert_eq!(budget.available(), MAX_PARALLEL_WORKERS);
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn budgeted_policy_skips_thread_query_below_byte_cutoff() {
        use std::cell::Cell;

        let budget = ParallelWorkerBudget::new(MAX_PARALLEL_WORKERS);
        let disclosures = generated_disclosures(PARALLEL_MIN_DISCLOSURES, 64);
        let thread_query_count = Cell::new(0usize);
        POLICY_TOTAL_SCAN_COUNT.with(|count| count.set(0));
        POLICY_BALANCE_SCAN_COUNT.with(|count| count.set(0));

        let mappings =
            preprocess_disclosures_with_budget_and_thread_supplier(&disclosures, &budget, || {
                thread_query_count.set(thread_query_count.get() + 1);
                MAX_PARALLEL_WORKERS
            })
            .unwrap();

        assert_eq!(mappings.ordered_disclosure_digests.len(), disclosures.len());
        assert_eq!(thread_query_count.get(), 0);
        assert_eq!(POLICY_TOTAL_SCAN_COUNT.with(std::cell::Cell::get), 1);
        assert_eq!(POLICY_BALANCE_SCAN_COUNT.with(std::cell::Cell::get), 0);
        assert_eq!(budget.available(), MAX_PARALLEL_WORKERS);
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
    fn benchmark_matrix_routes_match_measured_policy() {
        let available_threads = available_worker_threads();
        eprintln!("benchmark_host_available_parallelism={available_threads}");

        let payload_classes = [
            BenchmarkPayloadClass::Small,
            BenchmarkPayloadClass::Medium,
            BenchmarkPayloadClass::Large,
            BenchmarkPayloadClass::Mixed,
        ];

        for payload_class in payload_classes {
            for disclosure_count in [1, 8, 32, 128, 512] {
                let encoded_lengths = benchmark_encoded_lengths(disclosure_count, payload_class);
                let total_encoded_bytes: usize = encoded_lengths.iter().sum();
                let mode = mode_for_lengths(&encoded_lengths, available_threads);
                let expected = match (payload_class, disclosure_count, available_threads) {
                    (
                        BenchmarkPayloadClass::Large | BenchmarkPayloadClass::Mixed,
                        128 | 512,
                        2..,
                    ) => DisclosureExecutionMode::NativeParallel {
                        worker_count: available_threads.min(MAX_PARALLEL_WORKERS),
                    },
                    _ => DisclosureExecutionMode::Serial,
                };

                eprintln!(
                    "benchmark_route id={}/{} disclosures={} encoded_bytes={} mode={mode:?}",
                    payload_class.label(),
                    disclosure_count,
                    disclosure_count,
                    total_encoded_bytes,
                );
                assert_eq!(
                    mode,
                    expected,
                    "unexpected route for {}/{} with {} encoded bytes",
                    payload_class.label(),
                    disclosure_count,
                    total_encoded_bytes,
                );
            }
        }
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

        assert_eq!(
            select_execution_mode(&disclosures),
            DisclosureExecutionMode::Serial
        );
    }

    #[cfg(all(feature = "parallel", not(target_arch = "x86_64")))]
    #[test]
    fn unmeasured_architecture_parallel_feature_still_selects_serial_execution() {
        let disclosures = owned(&[OBJECT_DISCLOSURE, ARRAY_DISCLOSURE]);

        assert_eq!(
            select_execution_mode(&disclosures),
            DisclosureExecutionMode::Serial
        );
    }
}
