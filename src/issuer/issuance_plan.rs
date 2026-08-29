// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

//! Immutable SD-JWT issuance planning and deterministic assembly.
//!
//! Planning consumes disclosure and decoy randomness in the legacy depth-first
//! order and assigns stable job and compact structural-location identities
//! before any disclosure is encoded. The serial path remains the behavioral
//! oracle. A bounded native executor is available behind the `parallel` feature,
//! but production selection stays serial until issuance-specific crossover
//! thresholds have been qualified. Assembly validates an authoritative job
//! registry, restores disclosures by identity and ordinal, and rejects missing,
//! duplicate, swapped, or misplaced jobs before the issuer signs.

use serde_json::{json, Map, Value};
#[cfg(all(
    feature = "issuance_bench",
    feature = "parallel",
    target_arch = "x86_64"
))]
use std::cell::Cell;
#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
use std::collections::HashMap;
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
use std::thread;

#[cfg(test)]
use super::IssuanceOptions;
use super::{ClaimsForSelectiveDisclosureStrategy, IssuanceRandomSource, SDJWTIssuer};
use crate::disclosure::SDJWTDisclosure;
use crate::error::{Error, Result};
use crate::utils::base64_hash;
use crate::{SD_DIGESTS_KEY, SD_LIST_PREFIX};

type JobId = u64;
type LocationId = u64;

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
const MAX_PARALLEL_ISSUANCE_WORKERS: usize = 4;
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
const PARALLEL_ISSUANCE_WORKER_FAILURE: &str = "SD-JWT issuance executor failure: worker panicked";
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
const PARALLEL_ISSUANCE_SPAWN_FAILURE: &str =
    "SD-JWT issuance executor failure: could not spawn worker";

/// No production threshold is intentionally configured here. Issuance must be
/// benchmarked independently from verification before native execution can be
/// selected. Keeping the policy as data makes that later, evidence-backed
/// enablement an isolated change.
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
const QUALIFIED_ISSUANCE_THRESHOLDS: Option<IssuancePolicyThresholds> = None;

/// Mechanical eligibility only: this is not a qualified production policy.
/// It exists solely so the opt-in benchmark exercises the complete adaptive
/// selector, process-wide worker lease, and bounded native executor.
#[cfg(all(
    feature = "issuance_bench",
    feature = "parallel",
    target_arch = "x86_64"
))]
const BENCHMARK_ISSUANCE_THRESHOLDS: IssuancePolicyThresholds = IssuancePolicyThresholds {
    min_jobs: 2,
    min_estimated_work_bytes: 1,
};

#[cfg(all(
    feature = "issuance_bench",
    feature = "parallel",
    target_arch = "x86_64"
))]
pub(super) const BENCHMARK_ISSUANCE_WORKER_CAP: usize = MAX_PARALLEL_ISSUANCE_WORKERS;

#[cfg(all(
    feature = "issuance_bench",
    not(all(feature = "parallel", target_arch = "x86_64"))
))]
pub(super) const BENCHMARK_ISSUANCE_WORKER_CAP: usize = 1;

struct PlannedJob {
    job_id: JobId,
    location_id: LocationId,
    operation: PlannedJobOperation,
}

enum PlannedJobOperation {
    ObjectDisclosure {
        ordinal: usize,
        key: String,
        salt: String,
    },
    ArrayDisclosure {
        ordinal: usize,
        salt: String,
    },
    Decoy {
        salt: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PlannedJobKind {
    ObjectDisclosure,
    ArrayDisclosure,
    Decoy,
}

impl PlannedJobOperation {
    fn kind(&self) -> PlannedJobKind {
        match self {
            Self::ObjectDisclosure { .. } => PlannedJobKind::ObjectDisclosure,
            Self::ArrayDisclosure { .. } => PlannedJobKind::ArrayDisclosure,
            Self::Decoy { .. } => PlannedJobKind::Decoy,
        }
    }

    fn disclosure_ordinal(&self) -> Option<usize> {
        match self {
            Self::ObjectDisclosure { ordinal, .. } | Self::ArrayDisclosure { ordinal, .. } => {
                Some(*ordinal)
            }
            Self::Decoy { .. } => None,
        }
    }
}

struct PlannedValue {
    location_id: LocationId,
    kind: PlannedValueKind,
}

enum PlannedValueKind {
    Scalar(Value),
    Array(Vec<PlannedArrayEntry>),
    Object(PlannedObject),
}

enum PlannedArrayEntry {
    Visible(PlannedValue),
    Disclosed { value: PlannedValue, job_id: JobId },
}

enum PlannedObjectEntry {
    Visible { key: String, value: PlannedValue },
    Disclosed { value: PlannedValue, job_id: JobId },
}

struct PlannedObject {
    entries: Vec<PlannedObjectEntry>,
    decoy_job_ids: Vec<JobId>,
}

pub(super) struct IssuancePlan {
    root: PlannedValue,
    jobs: Vec<PlannedJob>,
    disclosure_job_ids: Vec<JobId>,
}

pub(super) struct IssuanceAssembly {
    pub(super) claims: Value,
    pub(super) disclosures: Vec<SDJWTDisclosure>,
}

#[cfg(feature = "issuance_bench")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct BenchmarkExecutionTraceSummary {
    pub(super) executor_batches: usize,
    pub(super) serial_batches: usize,
    pub(super) native_batches: usize,
    pub(super) budget_fallback_batches: usize,
    pub(super) max_worker_count: usize,
    pub(super) target_serial_fallback: bool,
}

#[cfg(all(
    feature = "issuance_bench",
    feature = "parallel",
    target_arch = "x86_64"
))]
#[derive(Default)]
struct BenchmarkExecutionTrace {
    executor_batches: Cell<usize>,
    serial_batches: Cell<usize>,
    native_batches: Cell<usize>,
    budget_fallback_batches: Cell<usize>,
    max_worker_count: Cell<usize>,
}

#[cfg(all(
    feature = "issuance_bench",
    feature = "parallel",
    target_arch = "x86_64"
))]
impl BenchmarkExecutionTrace {
    fn record_serial(&self) {
        self.executor_batches
            .set(self.executor_batches.get().saturating_add(1));
        self.serial_batches
            .set(self.serial_batches.get().saturating_add(1));
    }

    fn record_native(&self, worker_count: usize) {
        self.executor_batches
            .set(self.executor_batches.get().saturating_add(1));
        self.native_batches
            .set(self.native_batches.get().saturating_add(1));
        self.max_worker_count
            .set(self.max_worker_count.get().max(worker_count));
    }

    fn record_budget_fallback(&self) {
        self.executor_batches
            .set(self.executor_batches.get().saturating_add(1));
        self.serial_batches
            .set(self.serial_batches.get().saturating_add(1));
        self.budget_fallback_batches
            .set(self.budget_fallback_batches.get().saturating_add(1));
    }

    fn summary(&self) -> BenchmarkExecutionTraceSummary {
        BenchmarkExecutionTraceSummary {
            executor_batches: self.executor_batches.get(),
            serial_batches: self.serial_batches.get(),
            native_batches: self.native_batches.get(),
            budget_fallback_batches: self.budget_fallback_batches.get(),
            max_worker_count: self.max_worker_count.get(),
            target_serial_fallback: false,
        }
    }
}

impl IssuancePlan {
    pub(super) fn create<'a, R: IssuanceRandomSource>(
        claims: Value,
        strategy: ClaimsForSelectiveDisclosureStrategy<'a>,
        add_decoy_claims: bool,
        random_source: &mut R,
    ) -> Result<Self> {
        let mut planner = Planner {
            add_decoy_claims,
            next_location_id: 0,
            jobs: Vec::new(),
            disclosure_job_ids: Vec::new(),
        };
        let root_location_id = planner.allocate_location_id()?;
        let root = planner.plan_value(claims, strategy, root_location_id, random_source)?;

        Ok(Self {
            root,
            jobs: planner.jobs,
            disclosure_job_ids: planner.disclosure_job_ids,
        })
    }

    /// Execute through the production policy. Until an issuance benchmark has
    /// qualified native thresholds this is deliberately identical to the
    /// serial oracle, even when the `parallel` feature is enabled.
    pub(super) fn execute(self) -> Result<IssuanceAssembly> {
        #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
        {
            self.execute_adaptively(
                QUALIFIED_ISSUANCE_THRESHOLDS,
                &PARALLEL_ISSUANCE_WORKER_BUDGET,
                available_worker_threads,
            )
        }

        #[cfg(not(all(feature = "parallel", target_arch = "x86_64")))]
        {
            self.execute_serial()
        }
    }

    pub(super) fn execute_serial(self) -> Result<IssuanceAssembly> {
        let mut assembler = SerialAssembler::new(self.jobs, self.disclosure_job_ids)?;
        let claims = assembler.execute_value(self.root)?;
        assembler.finish(claims)
    }

    /// Exercise the candidate through the exact adaptive production machinery,
    /// but with mechanical benchmark eligibility rather than a production
    /// threshold. This method does not exist without the benchmark feature.
    #[cfg(feature = "issuance_bench")]
    pub(super) fn execute_benchmark_candidate(self) -> Result<IssuanceAssembly> {
        #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
        {
            self.execute_adaptively(
                Some(BENCHMARK_ISSUANCE_THRESHOLDS),
                &PARALLEL_ISSUANCE_WORKER_BUDGET,
                available_worker_threads,
            )
        }

        #[cfg(not(all(feature = "parallel", target_arch = "x86_64")))]
        {
            self.execute_serial()
        }
    }

    /// Untimed benchmark preflight variant that records the route selected for
    /// each ready batch. Timed iterations use `execute_benchmark_candidate`
    /// and therefore pay no tracing cost.
    #[cfg(feature = "issuance_bench")]
    pub(super) fn execute_benchmark_candidate_with_trace(
        self,
    ) -> Result<(IssuanceAssembly, BenchmarkExecutionTraceSummary)> {
        #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
        {
            let trace = BenchmarkExecutionTrace::default();
            let assembly = self.execute_with_executor(&AdaptiveIssuanceExecutor {
                thresholds: BENCHMARK_ISSUANCE_THRESHOLDS,
                budget: &PARALLEL_ISSUANCE_WORKER_BUDGET,
                available_threads: available_worker_threads,
                trace: Some(&trace),
            })?;
            Ok((assembly, trace.summary()))
        }

        #[cfg(not(all(feature = "parallel", target_arch = "x86_64")))]
        {
            let assembly = self.execute_serial()?;
            Ok((
                assembly,
                BenchmarkExecutionTraceSummary {
                    target_serial_fallback: true,
                    ..BenchmarkExecutionTraceSummary::default()
                },
            ))
        }
    }

    #[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
    fn execute_with_executor<E: IssuanceExecutor>(self, executor: &E) -> Result<IssuanceAssembly> {
        let mut assembler = SerialAssembler::new(self.jobs, self.disclosure_job_ids)?;
        let claims = assembler.execute_value_with_executor(self.root, executor)?;
        assembler.finish(claims)
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    fn execute_adaptively<F>(
        self,
        thresholds: Option<IssuancePolicyThresholds>,
        budget: &ParallelIssuanceWorkerBudget,
        available_threads: F,
    ) -> Result<IssuanceAssembly>
    where
        F: Fn() -> usize,
    {
        let Some(thresholds) = thresholds else {
            return self.execute_serial();
        };
        self.execute_with_executor(&AdaptiveIssuanceExecutor {
            thresholds,
            budget,
            available_threads,
            #[cfg(feature = "issuance_bench")]
            trace: None,
        })
    }
}

struct Planner {
    add_decoy_claims: bool,
    next_location_id: LocationId,
    jobs: Vec<PlannedJob>,
    disclosure_job_ids: Vec<JobId>,
}

impl Planner {
    fn plan_value<'a, R: IssuanceRandomSource>(
        &mut self,
        value: Value,
        strategy: ClaimsForSelectiveDisclosureStrategy<'a>,
        location_id: LocationId,
        random_source: &mut R,
    ) -> Result<PlannedValue> {
        let kind = match value {
            Value::Array(values) => self.plan_array(values, strategy, random_source)?,
            Value::Object(values) => {
                self.plan_object(values, strategy, location_id, random_source)?
            }
            scalar => PlannedValueKind::Scalar(scalar),
        };
        Ok(PlannedValue { location_id, kind })
    }

    fn plan_array<'a, R: IssuanceRandomSource>(
        &mut self,
        values: Vec<Value>,
        strategy: ClaimsForSelectiveDisclosureStrategy<'a>,
        random_source: &mut R,
    ) -> Result<PlannedValueKind> {
        let mut entries = Vec::with_capacity(values.len());

        for (index, value) in values.into_iter().enumerate() {
            let strategy_key = format!("[{index}]");
            let location_id = self.allocate_location_id()?;
            let planned_value = self.plan_value(
                value,
                strategy.next_level(&strategy_key),
                location_id,
                random_source,
            )?;
            let entry = if strategy.sd_for_key(&strategy_key) {
                PlannedArrayEntry::Disclosed {
                    value: planned_value,
                    job_id: self.plan_array_disclosure(location_id, random_source)?,
                }
            } else {
                PlannedArrayEntry::Visible(planned_value)
            };
            entries.push(entry);
        }

        Ok(PlannedValueKind::Array(entries))
    }

    fn plan_object<'a, R: IssuanceRandomSource>(
        &mut self,
        values: Map<String, Value>,
        strategy: ClaimsForSelectiveDisclosureStrategy<'a>,
        location_id: LocationId,
        random_source: &mut R,
    ) -> Result<PlannedValueKind> {
        let mut entries = Vec::with_capacity(values.len());

        for (key, value) in values {
            let child_location_id = self.allocate_location_id()?;
            let planned_value = self.plan_value(
                value,
                strategy.next_level(&key),
                child_location_id,
                random_source,
            )?;
            let entry = if strategy.sd_for_key(&key) {
                PlannedObjectEntry::Disclosed {
                    value: planned_value,
                    job_id: self.plan_object_disclosure(child_location_id, key, random_source)?,
                }
            } else {
                PlannedObjectEntry::Visible {
                    key,
                    value: planned_value,
                }
            };
            entries.push(entry);
        }

        let decoy_job_ids = if self.add_decoy_claims {
            let count = random_source
                .decoy_count(SDJWTIssuer::DECOY_MIN_ELEMENTS..SDJWTIssuer::DECOY_MAX_ELEMENTS);
            let mut decoys = Vec::with_capacity(count as usize);
            for _ in 0..count {
                decoys.push(self.plan_decoy(location_id, random_source)?);
            }
            decoys
        } else {
            Vec::new()
        };

        Ok(PlannedValueKind::Object(PlannedObject {
            entries,
            decoy_job_ids,
        }))
    }

    fn plan_object_disclosure<R: IssuanceRandomSource>(
        &mut self,
        location_id: LocationId,
        key: String,
        random_source: &mut R,
    ) -> Result<JobId> {
        let ordinal = self.disclosure_job_ids.len();
        let job_id = self.allocate_job_id()?;
        let salt = random_source.disclosure_salt();
        self.jobs.push(PlannedJob {
            job_id,
            location_id,
            operation: PlannedJobOperation::ObjectDisclosure { ordinal, key, salt },
        });
        self.disclosure_job_ids.push(job_id);
        Ok(job_id)
    }

    fn plan_array_disclosure<R: IssuanceRandomSource>(
        &mut self,
        location_id: LocationId,
        random_source: &mut R,
    ) -> Result<JobId> {
        let ordinal = self.disclosure_job_ids.len();
        let job_id = self.allocate_job_id()?;
        let salt = random_source.disclosure_salt();
        self.jobs.push(PlannedJob {
            job_id,
            location_id,
            operation: PlannedJobOperation::ArrayDisclosure { ordinal, salt },
        });
        self.disclosure_job_ids.push(job_id);
        Ok(job_id)
    }

    fn plan_decoy<R: IssuanceRandomSource>(
        &mut self,
        location_id: LocationId,
        random_source: &mut R,
    ) -> Result<JobId> {
        let job_id = self.allocate_job_id()?;
        let salt = random_source.decoy_salt();
        self.jobs.push(PlannedJob {
            job_id,
            location_id,
            operation: PlannedJobOperation::Decoy { salt },
        });
        Ok(job_id)
    }

    fn allocate_job_id(&self) -> Result<JobId> {
        JobId::try_from(self.jobs.len()).map_err(|_| invalid_plan("issuance job identity overflow"))
    }

    fn allocate_location_id(&mut self) -> Result<LocationId> {
        let location_id = self.next_location_id;
        self.next_location_id = self
            .next_location_id
            .checked_add(1)
            .ok_or_else(|| invalid_plan("issuance location identity overflow"))?;
        Ok(location_id)
    }
}

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IssuanceJobIdentity {
    job_id: JobId,
    location_id: LocationId,
    kind: PlannedJobKind,
    disclosure_ordinal: Option<usize>,
}

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
struct IssuanceJob {
    identity: IssuanceJobIdentity,
    operation: IssuanceJobOperation,
}

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
enum IssuanceJobOperation {
    ObjectDisclosure {
        key: String,
        salt: String,
        value: Value,
    },
    ArrayDisclosure {
        salt: String,
        value: Value,
    },
    Decoy {
        salt: String,
    },
}

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
enum IssuanceProduct {
    Disclosure(SDJWTDisclosure),
    DecoyDigest(String),
}

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
struct IssuanceOutcome {
    identity: IssuanceJobIdentity,
    result: Option<Result<IssuanceProduct>>,
}

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
type IssuanceWorker = fn(IssuanceJob) -> IssuanceOutcome;

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
trait IssuanceExecutor {
    fn execute(&self, jobs: Vec<IssuanceJob>) -> Result<Vec<IssuanceOutcome>>;
}

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
struct SerialIssuanceExecutor {
    worker: IssuanceWorker,
}

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
impl Default for SerialIssuanceExecutor {
    fn default() -> Self {
        Self {
            worker: process_issuance_job,
        }
    }
}

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
impl IssuanceExecutor for SerialIssuanceExecutor {
    fn execute(&self, jobs: Vec<IssuanceJob>) -> Result<Vec<IssuanceOutcome>> {
        Ok(jobs.into_iter().map(self.worker).collect())
    }
}

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
fn process_issuance_job(job: IssuanceJob) -> IssuanceOutcome {
    let IssuanceJob {
        identity,
        operation,
    } = job;
    let product = match operation {
        IssuanceJobOperation::ObjectDisclosure { key, salt, value } => {
            IssuanceProduct::Disclosure(SDJWTDisclosure::new_with_salt(Some(key), value, salt))
        }
        IssuanceJobOperation::ArrayDisclosure { salt, value } => {
            IssuanceProduct::Disclosure(SDJWTDisclosure::new_with_salt(None, value, salt))
        }
        IssuanceJobOperation::Decoy { salt } => {
            IssuanceProduct::DecoyDigest(base64_hash(salt.as_bytes()))
        }
    };

    IssuanceOutcome {
        identity,
        result: Some(Ok(product)),
    }
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
fn estimate_ready_job_work_bytes(jobs: &[IssuanceJob]) -> Option<usize> {
    fn estimate_value(value: &Value) -> Option<usize> {
        match value {
            Value::Null => Some(4),
            Value::Bool(true) => Some(4),
            Value::Bool(false) => Some(5),
            Value::Number(number) => Some(number.to_string().len()),
            // This is deliberately a cheap estimate. Benchmark-qualified
            // cutoffs must account for JSON escaping expansion.
            Value::String(string) => string.len().checked_add(2),
            Value::Array(values) => {
                let mut total = 2usize;
                for (index, value) in values.iter().enumerate() {
                    total = total.checked_add(usize::from(index != 0))?;
                    total = total.checked_add(estimate_value(value)?)?;
                }
                Some(total)
            }
            Value::Object(values) => {
                let mut total = 2usize;
                for (index, (key, value)) in values.iter().enumerate() {
                    total = total.checked_add(usize::from(index != 0))?;
                    total = total.checked_add(key.len().checked_add(3)?)?;
                    total = total.checked_add(estimate_value(value)?)?;
                }
                Some(total)
            }
        }
    }

    jobs.iter().try_fold(0usize, |total, job| {
        let bytes = match &job.operation {
            IssuanceJobOperation::ObjectDisclosure { key, salt, value } => salt
                .len()
                .checked_add(key.len())?
                .checked_add(estimate_value(value)?)?
                .checked_add(10)?,
            IssuanceJobOperation::ArrayDisclosure { salt, value } => salt
                .len()
                .checked_add(estimate_value(value)?)?
                .checked_add(6)?,
            IssuanceJobOperation::Decoy { salt } => salt.len(),
        };
        total.checked_add(bytes)
    })
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
struct NativeParallelIssuanceExecutor {
    worker_count: usize,
    worker: IssuanceWorker,
    #[cfg(test)]
    forced_spawn_failure_at: Option<usize>,
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
impl NativeParallelIssuanceExecutor {
    fn new(worker_count: usize) -> Self {
        Self {
            worker_count: worker_count.clamp(1, MAX_PARALLEL_ISSUANCE_WORKERS),
            worker: process_issuance_job,
            #[cfg(test)]
            forced_spawn_failure_at: None,
        }
    }

    #[cfg(test)]
    fn with_worker(worker_count: usize, worker: IssuanceWorker) -> Self {
        Self {
            worker_count: worker_count.clamp(1, MAX_PARALLEL_ISSUANCE_WORKERS),
            worker,
            forced_spawn_failure_at: None,
        }
    }

    #[cfg(test)]
    fn with_forced_spawn_failure(worker_count: usize, spawn_index: usize) -> Self {
        Self {
            worker_count: worker_count.clamp(1, MAX_PARALLEL_ISSUANCE_WORKERS),
            worker: process_issuance_job,
            forced_spawn_failure_at: Some(spawn_index),
        }
    }
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
fn static_chunk_size(job_count: usize, worker_count: usize) -> usize {
    debug_assert!(job_count != 0);
    debug_assert!(worker_count != 0);
    job_count / worker_count + usize::from(job_count % worker_count != 0)
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
impl IssuanceExecutor for NativeParallelIssuanceExecutor {
    fn execute(&self, jobs: Vec<IssuanceJob>) -> Result<Vec<IssuanceOutcome>> {
        if jobs.len() < 2 || self.worker_count < 2 {
            return SerialIssuanceExecutor {
                worker: self.worker,
            }
            .execute(jobs);
        }

        let worker_count = self.worker_count.min(jobs.len());
        let chunk_size = static_chunk_size(jobs.len(), worker_count);
        let worker = self.worker;

        thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            let mut remaining_jobs = jobs.into_iter();
            let mut spawn_failed = false;

            loop {
                let chunk = remaining_jobs.by_ref().take(chunk_size).collect::<Vec<_>>();
                if chunk.is_empty() {
                    break;
                }

                #[cfg(test)]
                if self.forced_spawn_failure_at == Some(handles.len()) {
                    spawn_failed = true;
                    break;
                }

                let handle = thread::Builder::new()
                    .name("sd-jwt-issuance-worker".to_owned())
                    .spawn_scoped(scope, move || {
                        chunk.into_iter().map(worker).collect::<Vec<_>>()
                    });
                match handle {
                    Ok(handle) => handles.push(handle),
                    Err(_) => {
                        spawn_failed = true;
                        break;
                    }
                }
            }

            let mut outcomes = Vec::new();
            let mut worker_panicked = false;
            for handle in handles {
                match handle.join() {
                    Ok(mut chunk_outcomes) => outcomes.append(&mut chunk_outcomes),
                    Err(_) => worker_panicked = true,
                }
            }

            if spawn_failed {
                Err(Error::InvalidState(
                    PARALLEL_ISSUANCE_SPAWN_FAILURE.to_owned(),
                ))
            } else if worker_panicked {
                Err(Error::InvalidState(
                    PARALLEL_ISSUANCE_WORKER_FAILURE.to_owned(),
                ))
            } else {
                Ok(outcomes)
            }
        })
    }
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct IssuancePolicyThresholds {
    min_jobs: usize,
    min_estimated_work_bytes: usize,
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IssuanceExecutionMode {
    Serial,
    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    NativeParallel {
        worker_count: usize,
    },
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
fn select_execution_mode<F>(
    jobs: &[IssuanceJob],
    thresholds: IssuancePolicyThresholds,
    available_threads: F,
) -> IssuanceExecutionMode
where
    F: FnOnce() -> usize,
{
    if jobs.len() < thresholds.min_jobs {
        return IssuanceExecutionMode::Serial;
    }

    let Some(estimated_work_bytes) = estimate_ready_job_work_bytes(jobs) else {
        return IssuanceExecutionMode::Serial;
    };
    if estimated_work_bytes < thresholds.min_estimated_work_bytes {
        return IssuanceExecutionMode::Serial;
    }

    let worker_count = available_threads()
        .min(MAX_PARALLEL_ISSUANCE_WORKERS)
        .min(jobs.len());
    if worker_count < 2 {
        IssuanceExecutionMode::Serial
    } else {
        IssuanceExecutionMode::NativeParallel { worker_count }
    }
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
fn available_worker_threads() -> usize {
    thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(1)
}

/// A non-blocking process-wide cap for native issuance workers. Contention
/// falls back to the exact serial oracle instead of queueing credentials or
/// multiplying worker threads across concurrent issuer calls.
#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
struct ParallelIssuanceWorkerBudget {
    available: AtomicUsize,
    capacity: usize,
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
impl ParallelIssuanceWorkerBudget {
    const fn new(capacity: usize) -> Self {
        Self {
            available: AtomicUsize::new(capacity),
            capacity,
        }
    }

    fn try_acquire(&self, worker_count: usize) -> Option<ParallelIssuanceWorkerLease<'_>> {
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
                    return Some(ParallelIssuanceWorkerLease {
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
struct ParallelIssuanceWorkerLease<'a> {
    budget: &'a ParallelIssuanceWorkerBudget,
    worker_count: usize,
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
impl ParallelIssuanceWorkerLease<'_> {
    fn worker_count(&self) -> usize {
        self.worker_count
    }
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
impl Drop for ParallelIssuanceWorkerLease<'_> {
    fn drop(&mut self) {
        let previously_available = self
            .budget
            .available
            .fetch_add(self.worker_count, Ordering::Release);
        debug_assert!(
            previously_available <= self.budget.capacity - self.worker_count,
            "parallel issuance worker budget over-release"
        );
    }
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
static PARALLEL_ISSUANCE_WORKER_BUDGET: ParallelIssuanceWorkerBudget =
    ParallelIssuanceWorkerBudget::new(MAX_PARALLEL_ISSUANCE_WORKERS);

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
struct AdaptiveIssuanceExecutor<'a, F> {
    thresholds: IssuancePolicyThresholds,
    budget: &'a ParallelIssuanceWorkerBudget,
    available_threads: F,
    #[cfg(feature = "issuance_bench")]
    trace: Option<&'a BenchmarkExecutionTrace>,
}

#[cfg(all(feature = "parallel", target_arch = "x86_64"))]
impl<F> IssuanceExecutor for AdaptiveIssuanceExecutor<'_, F>
where
    F: Fn() -> usize,
{
    fn execute(&self, jobs: Vec<IssuanceJob>) -> Result<Vec<IssuanceOutcome>> {
        let mode = select_execution_mode(&jobs, self.thresholds, || (self.available_threads)());
        let IssuanceExecutionMode::NativeParallel { worker_count } = mode else {
            #[cfg(feature = "issuance_bench")]
            if let Some(trace) = self.trace {
                trace.record_serial();
            }
            return SerialIssuanceExecutor::default().execute(jobs);
        };
        let Some(lease) = self.budget.try_acquire(worker_count) else {
            #[cfg(feature = "issuance_bench")]
            if let Some(trace) = self.trace {
                trace.record_budget_fallback();
            }
            return SerialIssuanceExecutor::default().execute(jobs);
        };

        #[cfg(feature = "issuance_bench")]
        if let Some(trace) = self.trace {
            trace.record_native(lease.worker_count());
        }

        let outcomes = NativeParallelIssuanceExecutor::new(lease.worker_count()).execute(jobs);
        // Every scoped worker has joined. Release permits before deterministic
        // restoration, parent assembly, signing, or another ready batch.
        drop(lease);
        outcomes
    }
}

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
struct RestoredIssuanceJob {
    identity: IssuanceJobIdentity,
    product: IssuanceProduct,
}

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
fn execute_and_restore<E: IssuanceExecutor>(
    executor: &E,
    jobs: Vec<IssuanceJob>,
) -> Result<Vec<RestoredIssuanceJob>> {
    if jobs.is_empty() {
        return Ok(Vec::new());
    }

    let expected = jobs.iter().map(|job| job.identity).collect::<Vec<_>>();
    let outcomes = executor.execute(jobs)?;
    restore_issuance_outcomes(&expected, outcomes)
}

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
fn restore_issuance_outcomes(
    expected: &[IssuanceJobIdentity],
    outcomes: Vec<IssuanceOutcome>,
) -> Result<Vec<RestoredIssuanceJob>> {
    let expected_by_id = expected
        .iter()
        .enumerate()
        .map(|(index, identity)| (identity.job_id, index))
        .collect::<HashMap<_, _>>();
    if expected_by_id.len() != expected.len() {
        return Err(executor_contract_error(
            "planned issuance job identities are not unique",
        ));
    }

    let mut slots = std::iter::repeat_with(|| None)
        .take(expected.len())
        .collect::<Vec<Option<IssuanceOutcome>>>();
    let mut unexpected_identity = false;
    let mut duplicate_identity = false;
    let mut misplaced_identity = false;

    for outcome in outcomes {
        let Some(index) = expected_by_id.get(&outcome.identity.job_id).copied() else {
            unexpected_identity = true;
            continue;
        };
        if slots[index].is_some() {
            duplicate_identity = true;
            continue;
        }
        if outcome.identity != expected[index] {
            misplaced_identity = true;
        }
        slots[index] = Some(outcome);
    }

    // Contract-error precedence is independent of worker completion order and
    // does not include per-item identities or claim data.
    if unexpected_identity {
        return Err(executor_contract_error(
            "an unexpected issuance result identity was returned",
        ));
    }
    if duplicate_identity {
        return Err(executor_contract_error(
            "an issuance result identity was returned more than once",
        ));
    }
    if misplaced_identity {
        return Err(executor_contract_error(
            "an issuance result was bound to the wrong planned location or kind",
        ));
    }
    if slots.iter().any(Option::is_none) {
        return Err(executor_contract_error(
            "a planned issuance result was not returned",
        ));
    }

    slots
        .into_iter()
        .zip(expected.iter().copied())
        .map(|(outcome, identity)| {
            let outcome = outcome.ok_or_else(|| {
                executor_contract_error("a planned issuance result was not returned")
            })?;
            let product = outcome.result.ok_or_else(|| {
                executor_contract_error("an issuance result contained no worker output")
            })??;
            match (identity.kind, &product) {
                (
                    PlannedJobKind::ObjectDisclosure | PlannedJobKind::ArrayDisclosure,
                    IssuanceProduct::Disclosure(_),
                )
                | (PlannedJobKind::Decoy, IssuanceProduct::DecoyDigest(_)) => {}
                _ => {
                    return Err(executor_contract_error(
                        "an issuance result has the wrong result kind",
                    ))
                }
            }
            Ok(RestoredIssuanceJob { identity, product })
        })
        .collect()
}

#[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
fn executor_contract_error(message: &str) -> Error {
    Error::InvalidState(format!("invalid issuance executor result: {message}"))
}

struct SerialAssembler {
    disclosures: Vec<Option<SDJWTDisclosure>>,
    jobs: Vec<Option<PlannedJob>>,
    disclosure_job_ids: Vec<JobId>,
}

impl SerialAssembler {
    fn new(jobs: Vec<PlannedJob>, disclosure_job_ids: Vec<JobId>) -> Result<Self> {
        Self::validate_registry(&jobs, &disclosure_job_ids)?;
        Ok(Self {
            disclosures: std::iter::repeat_with(|| None)
                .take(disclosure_job_ids.len())
                .collect(),
            jobs: jobs.into_iter().map(Some).collect(),
            disclosure_job_ids,
        })
    }

    fn validate_registry(jobs: &[PlannedJob], disclosure_job_ids: &[JobId]) -> Result<()> {
        for (index, job) in jobs.iter().enumerate() {
            let expected_job_id = JobId::try_from(index)
                .map_err(|_| invalid_plan("issuance job registry exceeds identity capacity"))?;
            if job.job_id != expected_job_id {
                return Err(invalid_plan(
                    "a job descriptor identity does not match its registry index",
                ));
            }

            if let Some(ordinal) = job.operation.disclosure_ordinal() {
                let bound_job_id = disclosure_job_ids
                    .get(ordinal)
                    .ok_or_else(|| invalid_plan("a disclosure ordinal is out of bounds"))?;
                if *bound_job_id != job.job_id {
                    return Err(invalid_plan(
                        "a disclosure ordinal is bound to the wrong job identity",
                    ));
                }
            }
        }

        for (ordinal, job_id) in disclosure_job_ids.iter().copied().enumerate() {
            let index = usize::try_from(job_id)
                .map_err(|_| invalid_plan("a disclosure job identity exceeds platform capacity"))?;
            let job = jobs
                .get(index)
                .ok_or_else(|| invalid_plan("a disclosure job identity is out of bounds"))?;
            if job.operation.disclosure_ordinal() != Some(ordinal) {
                return Err(invalid_plan(
                    "a disclosure registry entry is bound to the wrong ordinal",
                ));
            }
        }

        Ok(())
    }

    fn execute_value(&mut self, value: PlannedValue) -> Result<Value> {
        let PlannedValue {
            location_id, kind, ..
        } = value;
        match kind {
            PlannedValueKind::Scalar(value) => Ok(value),
            PlannedValueKind::Array(entries) => self.execute_array(entries),
            PlannedValueKind::Object(object) => self.execute_object(location_id, object),
        }
    }

    #[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
    fn execute_value_with_executor<E: IssuanceExecutor>(
        &mut self,
        value: PlannedValue,
        executor: &E,
    ) -> Result<Value> {
        let PlannedValue {
            location_id, kind, ..
        } = value;
        match kind {
            PlannedValueKind::Scalar(value) => Ok(value),
            PlannedValueKind::Array(entries) => self.execute_array_with_executor(entries, executor),
            PlannedValueKind::Object(object) => {
                self.execute_object_with_executor(location_id, object, executor)
            }
        }
    }

    fn execute_array(&mut self, entries: Vec<PlannedArrayEntry>) -> Result<Value> {
        let mut claims = Vec::with_capacity(entries.len());

        for entry in entries {
            match entry {
                PlannedArrayEntry::Visible(value) => {
                    claims.push(self.execute_value(value)?);
                }
                PlannedArrayEntry::Disclosed { value, job_id } => {
                    let location_id = value.location_id;
                    let subtree = self.execute_value(value)?;
                    let operation =
                        self.take_job(job_id, location_id, PlannedJobKind::ArrayDisclosure)?;
                    let PlannedJobOperation::ArrayDisclosure { ordinal, salt } = operation else {
                        return Err(invalid_plan("an array entry references the wrong job kind"));
                    };
                    let disclosure = SDJWTDisclosure::new_with_salt(None, subtree, salt);
                    claims.push(json!({ SD_LIST_PREFIX: disclosure.hash }));
                    self.record_disclosure(job_id, ordinal, disclosure)?;
                }
            }
        }

        Ok(Value::Array(claims))
    }

    #[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
    fn execute_array_with_executor<E: IssuanceExecutor>(
        &mut self,
        entries: Vec<PlannedArrayEntry>,
        executor: &E,
    ) -> Result<Value> {
        enum ArrayOutput {
            Visible(Value),
            Disclosure(usize),
        }

        let mut outputs = Vec::with_capacity(entries.len());
        let mut jobs = Vec::new();

        for entry in entries {
            match entry {
                PlannedArrayEntry::Visible(value) => outputs.push(ArrayOutput::Visible(
                    self.execute_value_with_executor(value, executor)?,
                )),
                PlannedArrayEntry::Disclosed { value, job_id } => {
                    let location_id = value.location_id;
                    let subtree = self.execute_value_with_executor(value, executor)?;
                    let planned_job = self.take_planned_job(
                        job_id,
                        location_id,
                        PlannedJobKind::ArrayDisclosure,
                    )?;
                    let PlannedJobOperation::ArrayDisclosure { ordinal, salt } =
                        planned_job.operation
                    else {
                        return Err(invalid_plan("an array entry references the wrong job kind"));
                    };
                    let job_index = jobs.len();
                    jobs.push(IssuanceJob {
                        identity: IssuanceJobIdentity {
                            job_id,
                            location_id,
                            kind: PlannedJobKind::ArrayDisclosure,
                            disclosure_ordinal: Some(ordinal),
                        },
                        operation: IssuanceJobOperation::ArrayDisclosure {
                            salt,
                            value: subtree,
                        },
                    });
                    outputs.push(ArrayOutput::Disclosure(job_index));
                }
            }
        }

        let restored = execute_and_restore(executor, jobs)?;
        let mut restored = restored.into_iter().map(Some).collect::<Vec<_>>();
        let mut claims = Vec::with_capacity(outputs.len());
        for output in outputs {
            match output {
                ArrayOutput::Visible(value) => claims.push(value),
                ArrayOutput::Disclosure(job_index) => {
                    let RestoredIssuanceJob { identity, product } = restored
                        .get_mut(job_index)
                        .and_then(Option::take)
                        .ok_or_else(|| invalid_plan("an array disclosure result is missing"))?;
                    let IssuanceProduct::Disclosure(disclosure) = product else {
                        return Err(executor_contract_error(
                            "an array disclosure returned the wrong result kind",
                        ));
                    };
                    let ordinal = identity.disclosure_ordinal.ok_or_else(|| {
                        executor_contract_error("an array disclosure result has no ordinal")
                    })?;
                    claims.push(json!({ SD_LIST_PREFIX: disclosure.hash }));
                    self.record_disclosure(identity.job_id, ordinal, disclosure)?;
                }
            }
        }

        Ok(Value::Array(claims))
    }

    fn execute_object(&mut self, location_id: LocationId, object: PlannedObject) -> Result<Value> {
        let mut claims = Map::new();
        claims.insert(SD_DIGESTS_KEY.to_owned(), Value::Null);
        let mut digests = Vec::with_capacity(object.entries.len() + object.decoy_job_ids.len());

        for entry in object.entries {
            match entry {
                PlannedObjectEntry::Visible { key, value } => {
                    claims.insert(key, self.execute_value(value)?);
                }
                PlannedObjectEntry::Disclosed { value, job_id } => {
                    let child_location_id = value.location_id;
                    let subtree = self.execute_value(value)?;
                    let operation =
                        self.take_job(job_id, child_location_id, PlannedJobKind::ObjectDisclosure)?;
                    let PlannedJobOperation::ObjectDisclosure { ordinal, key, salt } = operation
                    else {
                        return Err(invalid_plan(
                            "an object entry references the wrong job kind",
                        ));
                    };
                    let disclosure = SDJWTDisclosure::new_with_salt(Some(key), subtree, salt);
                    digests.push(disclosure.hash.clone());
                    self.record_disclosure(job_id, ordinal, disclosure)?;
                }
            }
        }

        for job_id in object.decoy_job_ids {
            let operation = self.take_job(job_id, location_id, PlannedJobKind::Decoy)?;
            let PlannedJobOperation::Decoy { salt } = operation else {
                return Err(invalid_plan("a decoy entry references the wrong job kind"));
            };
            digests.push(base64_hash(salt.as_bytes()));
        }

        if digests.is_empty() {
            claims.shift_remove(SD_DIGESTS_KEY);
        } else {
            digests.sort();
            claims.insert(
                SD_DIGESTS_KEY.to_owned(),
                Value::Array(digests.into_iter().map(Value::String).collect()),
            );
        }

        Ok(Value::Object(claims))
    }

    #[cfg(any(test, all(feature = "parallel", target_arch = "x86_64")))]
    fn execute_object_with_executor<E: IssuanceExecutor>(
        &mut self,
        location_id: LocationId,
        object: PlannedObject,
        executor: &E,
    ) -> Result<Value> {
        let mut claims = Map::new();
        claims.insert(SD_DIGESTS_KEY.to_owned(), Value::Null);
        let mut jobs = Vec::with_capacity(object.entries.len() + object.decoy_job_ids.len());

        for entry in object.entries {
            match entry {
                PlannedObjectEntry::Visible { key, value } => {
                    claims.insert(key, self.execute_value_with_executor(value, executor)?);
                }
                PlannedObjectEntry::Disclosed { value, job_id } => {
                    let child_location_id = value.location_id;
                    let subtree = self.execute_value_with_executor(value, executor)?;
                    let planned_job = self.take_planned_job(
                        job_id,
                        child_location_id,
                        PlannedJobKind::ObjectDisclosure,
                    )?;
                    let PlannedJobOperation::ObjectDisclosure { ordinal, key, salt } =
                        planned_job.operation
                    else {
                        return Err(invalid_plan(
                            "an object entry references the wrong job kind",
                        ));
                    };
                    jobs.push(IssuanceJob {
                        identity: IssuanceJobIdentity {
                            job_id,
                            location_id: child_location_id,
                            kind: PlannedJobKind::ObjectDisclosure,
                            disclosure_ordinal: Some(ordinal),
                        },
                        operation: IssuanceJobOperation::ObjectDisclosure {
                            key,
                            salt,
                            value: subtree,
                        },
                    });
                }
            }
        }

        for job_id in object.decoy_job_ids {
            let planned_job = self.take_planned_job(job_id, location_id, PlannedJobKind::Decoy)?;
            let PlannedJobOperation::Decoy { salt } = planned_job.operation else {
                return Err(invalid_plan("a decoy entry references the wrong job kind"));
            };
            jobs.push(IssuanceJob {
                identity: IssuanceJobIdentity {
                    job_id,
                    location_id,
                    kind: PlannedJobKind::Decoy,
                    disclosure_ordinal: None,
                },
                operation: IssuanceJobOperation::Decoy { salt },
            });
        }

        let restored = execute_and_restore(executor, jobs)?;
        let mut digests = Vec::with_capacity(restored.len());
        for RestoredIssuanceJob { identity, product } in restored {
            match product {
                IssuanceProduct::Disclosure(disclosure) => {
                    let ordinal = identity.disclosure_ordinal.ok_or_else(|| {
                        executor_contract_error("an object disclosure result has no ordinal")
                    })?;
                    digests.push(disclosure.hash.clone());
                    self.record_disclosure(identity.job_id, ordinal, disclosure)?;
                }
                IssuanceProduct::DecoyDigest(digest) => digests.push(digest),
            }
        }

        if digests.is_empty() {
            claims.shift_remove(SD_DIGESTS_KEY);
        } else {
            digests.sort();
            claims.insert(
                SD_DIGESTS_KEY.to_owned(),
                Value::Array(digests.into_iter().map(Value::String).collect()),
            );
        }

        Ok(Value::Object(claims))
    }

    fn take_job(
        &mut self,
        job_id: JobId,
        location_id: LocationId,
        expected_kind: PlannedJobKind,
    ) -> Result<PlannedJobOperation> {
        Ok(self
            .take_planned_job(job_id, location_id, expected_kind)?
            .operation)
    }

    fn take_planned_job(
        &mut self,
        job_id: JobId,
        location_id: LocationId,
        expected_kind: PlannedJobKind,
    ) -> Result<PlannedJob> {
        let index = usize::try_from(job_id)
            .map_err(|_| invalid_plan("an issuance job identity exceeds platform capacity"))?;
        let slot = self
            .jobs
            .get_mut(index)
            .ok_or_else(|| invalid_plan("an issuance job identity is out of bounds"))?;
        let job = slot
            .take()
            .ok_or_else(|| invalid_plan("an issuance job was executed more than once"))?;
        if job.job_id != job_id {
            return Err(invalid_plan("an issuance job returned the wrong identity"));
        }
        if job.location_id != location_id {
            return Err(invalid_plan(
                "an issuance job was restored at the wrong structural location",
            ));
        }
        if job.operation.kind() != expected_kind {
            return Err(invalid_plan("an issuance job has the wrong operation kind"));
        }
        Ok(job)
    }

    fn record_disclosure(
        &mut self,
        job_id: JobId,
        ordinal: usize,
        disclosure: SDJWTDisclosure,
    ) -> Result<()> {
        if self.disclosure_job_ids.get(ordinal) != Some(&job_id) {
            return Err(invalid_plan(
                "a disclosure result is bound to the wrong job identity",
            ));
        }
        let slot = self
            .disclosures
            .get_mut(ordinal)
            .ok_or_else(|| invalid_plan("a disclosure ordinal is out of bounds"))?;
        if slot.is_some() {
            return Err(invalid_plan("a disclosure ordinal appears more than once"));
        }
        *slot = Some(disclosure);
        Ok(())
    }

    fn finish(self, claims: Value) -> Result<IssuanceAssembly> {
        if self.jobs.iter().any(Option::is_some) {
            return Err(invalid_plan("not every issuance job was executed"));
        }

        let disclosures = self
            .disclosures
            .into_iter()
            .map(|disclosure| {
                disclosure.ok_or_else(|| invalid_plan("a planned disclosure result is missing"))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(IssuanceAssembly {
            claims,
            disclosures,
        })
    }
}

fn invalid_plan(message: &str) -> Error {
    Error::InvalidState(format!("invalid issuance plan: {message}"))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::ops::Range;
    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    use std::sync::atomic::{AtomicUsize as TestAtomicUsize, Ordering as TestOrdering};
    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    use std::time::Duration;

    use jsonwebtoken::EncodingKey;
    use serde_json::json;

    use super::*;
    use crate::utils::base64url_decode;

    #[derive(Debug, Eq, PartialEq)]
    enum RandomEvent {
        Disclosure(String),
        DecoyCount(u32),
        DecoySalt(String),
    }

    struct RecordingRandomSource {
        next_disclosure_salt: usize,
        decoy_counts: VecDeque<u32>,
        next_decoy_salt: usize,
        events: Vec<RandomEvent>,
    }

    impl RecordingRandomSource {
        fn with_decoy_counts(counts: impl IntoIterator<Item = u32>) -> Self {
            Self {
                next_disclosure_salt: 0,
                decoy_counts: counts.into_iter().collect(),
                next_decoy_salt: 0,
                events: Vec::new(),
            }
        }
    }

    impl IssuanceRandomSource for RecordingRandomSource {
        fn disclosure_salt(&mut self) -> String {
            let salt = format!("disclosure-{}", self.next_disclosure_salt);
            self.next_disclosure_salt += 1;
            self.events.push(RandomEvent::Disclosure(salt.clone()));
            salt
        }

        fn decoy_count(&mut self, range: Range<u32>) -> u32 {
            let count = self
                .decoy_counts
                .pop_front()
                .expect("decoy-count tape must not be exhausted");
            assert!(range.contains(&count));
            self.events.push(RandomEvent::DecoyCount(count));
            count
        }

        fn decoy_salt(&mut self) -> String {
            let salt = format!("decoy-{}", self.next_decoy_salt);
            self.next_decoy_salt += 1;
            self.events.push(RandomEvent::DecoySalt(salt.clone()));
            salt
        }
    }

    fn two_disclosure_plan() -> IssuancePlan {
        let mut random_source = RecordingRandomSource::with_decoy_counts([]);
        IssuancePlan::create(
            json!({ "first": 1, "second": 2 }),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            false,
            &mut random_source,
        )
        .unwrap()
    }

    fn nested_plan(add_decoy_claims: bool) -> IssuancePlan {
        let decoy_counts = if add_decoy_claims {
            vec![2, 3]
        } else {
            Vec::new()
        };
        let mut random_source = RecordingRandomSource::with_decoy_counts(decoy_counts);
        IssuancePlan::create(
            json!({
                "profile": { "name": "Alice", "city": "München" },
                "roles": ["admin", "reader"],
                "active": true
            }),
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            add_decoy_claims,
            &mut random_source,
        )
        .unwrap()
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    fn policy_jobs(count: usize, value_bytes: usize) -> Vec<IssuanceJob> {
        (0..count)
            .map(|ordinal| IssuanceJob {
                identity: IssuanceJobIdentity {
                    job_id: JobId::try_from(ordinal).unwrap(),
                    location_id: LocationId::try_from(ordinal).unwrap(),
                    kind: PlannedJobKind::ObjectDisclosure,
                    disclosure_ordinal: Some(ordinal),
                },
                operation: IssuanceJobOperation::ObjectDisclosure {
                    key: format!("claim-{ordinal}"),
                    salt: format!("salt-{ordinal}"),
                    value: Value::String("x".repeat(value_bytes)),
                },
            })
            .collect()
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    fn selector_accounting_jobs() -> Vec<IssuanceJob> {
        vec![
            IssuanceJob {
                identity: IssuanceJobIdentity {
                    job_id: 0,
                    location_id: 0,
                    kind: PlannedJobKind::ObjectDisclosure,
                    disclosure_ordinal: Some(0),
                },
                operation: IssuanceJobOperation::ObjectDisclosure {
                    key: "k".to_owned(),
                    salt: "s".to_owned(),
                    value: Value::Bool(true),
                },
            },
            IssuanceJob {
                identity: IssuanceJobIdentity {
                    job_id: 1,
                    location_id: 1,
                    kind: PlannedJobKind::ArrayDisclosure,
                    disclosure_ordinal: Some(1),
                },
                operation: IssuanceJobOperation::ArrayDisclosure {
                    salt: "s".to_owned(),
                    value: Value::Bool(false),
                },
            },
            IssuanceJob {
                identity: IssuanceJobIdentity {
                    job_id: 2,
                    location_id: 2,
                    kind: PlannedJobKind::Decoy,
                    disclosure_ordinal: None,
                },
                operation: IssuanceJobOperation::Decoy {
                    salt: "xyz".to_owned(),
                },
            },
            IssuanceJob {
                identity: IssuanceJobIdentity {
                    job_id: 3,
                    location_id: 3,
                    kind: PlannedJobKind::ObjectDisclosure,
                    disclosure_ordinal: Some(2),
                },
                operation: IssuanceJobOperation::ObjectDisclosure {
                    key: "k".to_owned(),
                    salt: "s".to_owned(),
                    value: Value::Bool(true),
                },
            },
            IssuanceJob {
                identity: IssuanceJobIdentity {
                    job_id: 4,
                    location_id: 4,
                    kind: PlannedJobKind::ArrayDisclosure,
                    disclosure_ordinal: Some(3),
                },
                operation: IssuanceJobOperation::ArrayDisclosure {
                    salt: "s".to_owned(),
                    value: Value::Bool(false),
                },
            },
        ]
    }

    fn assert_assemblies_equal(expected: &IssuanceAssembly, actual: &IssuanceAssembly) {
        assert_eq!(actual.claims, expected.claims);
        assert_eq!(actual.disclosures.len(), expected.disclosures.len());
        for (actual, expected) in actual.disclosures.iter().zip(&expected.disclosures) {
            assert_eq!(actual.raw_b64, expected.raw_b64);
            assert_eq!(actual.hash, expected.hash);
        }
    }

    fn deterministic_shuffle<T>(values: &mut [T]) {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for upper in (1..values.len()).rev() {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            values.swap(upper, (state as usize) % (upper + 1));
        }
    }

    struct ShufflingIssuanceExecutor;

    impl IssuanceExecutor for ShufflingIssuanceExecutor {
        fn execute(&self, jobs: Vec<IssuanceJob>) -> Result<Vec<IssuanceOutcome>> {
            let mut outcomes = SerialIssuanceExecutor::default().execute(jobs)?;
            deterministic_shuffle(&mut outcomes);
            Ok(outcomes)
        }
    }

    #[derive(Clone, Copy)]
    enum OutcomeMutation {
        Missing,
        Duplicate,
        Misplaced,
        MissingWorkerOutput,
        WrongResultKind,
        Unexpected,
    }

    struct MutatingIssuanceExecutor(OutcomeMutation);

    impl IssuanceExecutor for MutatingIssuanceExecutor {
        fn execute(&self, jobs: Vec<IssuanceJob>) -> Result<Vec<IssuanceOutcome>> {
            let mut outcomes = SerialIssuanceExecutor::default().execute(jobs)?;
            assert!(outcomes.len() >= 2, "mutation fixture requires two jobs");
            match self.0 {
                OutcomeMutation::Missing => {
                    outcomes.pop();
                }
                OutcomeMutation::Duplicate => outcomes[1].identity = outcomes[0].identity,
                OutcomeMutation::Misplaced => {
                    outcomes[0].identity.location_id = LocationId::MAX;
                }
                OutcomeMutation::MissingWorkerOutput => outcomes[0].result = None,
                OutcomeMutation::WrongResultKind => {
                    outcomes[0].result =
                        Some(Ok(IssuanceProduct::DecoyDigest("wrong-kind".to_owned())));
                }
                OutcomeMutation::Unexpected => outcomes[0].identity.job_id = JobId::MAX,
            }
            outcomes.reverse();
            Ok(outcomes)
        }
    }

    fn assert_executor_error(executor: &impl IssuanceExecutor, expected_message: &str) {
        let error = match two_disclosure_plan().execute_with_executor(executor) {
            Ok(_) => panic!("corrupted executor output must fail closed"),
            Err(error) => error,
        };
        match error {
            Error::InvalidState(message) => assert_eq!(message, expected_message),
            other => panic!("unexpected executor error: {other:?}"),
        }
    }

    fn object_entries_mut(plan: &mut IssuancePlan) -> &mut [PlannedObjectEntry] {
        match &mut plan.root.kind {
            PlannedValueKind::Object(object) => &mut object.entries,
            _ => panic!("test plan root must be an object"),
        }
    }

    fn disclosed_job_id_mut(entry: &mut PlannedObjectEntry) -> &mut JobId {
        match entry {
            PlannedObjectEntry::Disclosed { job_id, .. } => job_id,
            PlannedObjectEntry::Visible { .. } => panic!("test entry must be disclosed"),
        }
    }

    fn disclosure_ordinal_mut(job: &mut PlannedJob) -> &mut usize {
        match &mut job.operation {
            PlannedJobOperation::ObjectDisclosure { ordinal, .. }
            | PlannedJobOperation::ArrayDisclosure { ordinal, .. } => ordinal,
            PlannedJobOperation::Decoy { .. } => panic!("test job must be a disclosure"),
        }
    }

    fn assert_invalid_plan(plan: IssuancePlan, expected_message: &str) {
        let error = match plan.execute_serial() {
            Ok(_) => panic!("corrupted issuance plan must fail closed"),
            Err(error) => error,
        };
        match error {
            Error::InvalidState(message) => assert_eq!(message, expected_message),
            other => panic!("unexpected error for corrupted issuance plan: {other:?}"),
        }
    }

    #[test]
    fn planning_assigns_disclosure_ids_and_randomness_in_depth_first_postorder() {
        let claims = json!({
            "profile": { "name": "Alice" },
            "roles": ["admin"]
        });
        let mut random_source = RecordingRandomSource::with_decoy_counts([]);

        let plan = IssuancePlan::create(
            claims,
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            false,
            &mut random_source,
        )
        .unwrap();

        assert_eq!(plan.disclosure_job_ids, vec![0, 1, 2, 3]);
        assert_eq!(
            plan.jobs.iter().map(|job| job.job_id).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert_eq!(
            random_source.events,
            vec![
                RandomEvent::Disclosure("disclosure-0".to_owned()),
                RandomEvent::Disclosure("disclosure-1".to_owned()),
                RandomEvent::Disclosure("disclosure-2".to_owned()),
                RandomEvent::Disclosure("disclosure-3".to_owned()),
            ]
        );

        let assembly = plan.execute_serial().unwrap();
        assert_eq!(assembly.disclosures.len(), 4);
        let decoded = assembly
            .disclosures
            .iter()
            .map(|disclosure| {
                serde_json::from_slice::<Value>(
                    &base64url_decode(&disclosure.raw_b64)
                        .expect("planned disclosure must be valid Base64url"),
                )
                .expect("planned disclosure must be valid JSON")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            decoded
                .iter()
                .map(|disclosure| disclosure[0].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "disclosure-0",
                "disclosure-1",
                "disclosure-2",
                "disclosure-3",
            ]
        );
        assert_eq!(decoded[0][1], "name");
        assert_eq!(decoded[1][1], "profile");
        assert_eq!(decoded[2][1], "admin");
        assert_eq!(decoded[3][1], "roles");
        assert_eq!(
            decoded[1][2][SD_DIGESTS_KEY][0],
            assembly.disclosures[0].hash
        );
        assert_eq!(
            decoded[3][2][0][SD_LIST_PREFIX],
            assembly.disclosures[2].hash
        );
    }

    #[test]
    fn planning_allocates_nested_decoys_before_parent_decoys() {
        let claims = json!({ "nested": { "value": 1 } });
        let mut random_source = RecordingRandomSource::with_decoy_counts([2, 3]);

        let plan = IssuancePlan::create(
            claims,
            ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
            true,
            &mut random_source,
        )
        .unwrap();

        assert!(plan.disclosure_job_ids.is_empty());
        assert_eq!(plan.jobs.len(), 5);
        assert_eq!(
            random_source.events,
            vec![
                RandomEvent::DecoyCount(2),
                RandomEvent::DecoySalt("decoy-0".to_owned()),
                RandomEvent::DecoySalt("decoy-1".to_owned()),
                RandomEvent::DecoyCount(3),
                RandomEvent::DecoySalt("decoy-2".to_owned()),
                RandomEvent::DecoySalt("decoy-3".to_owned()),
                RandomEvent::DecoySalt("decoy-4".to_owned()),
            ]
        );

        let assembly = plan.execute_serial().unwrap();
        assert!(assembly.disclosures.is_empty());
        assert_eq!(
            assembly.claims["nested"][SD_DIGESTS_KEY]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(assembly.claims[SD_DIGESTS_KEY].as_array().unwrap().len(), 3);
    }

    #[test]
    fn serial_assembly_rejects_duplicate_job_identity() {
        let mut plan = two_disclosure_plan();
        plan.jobs[1].job_id = plan.jobs[0].job_id;

        assert_invalid_plan(
            plan,
            "invalid issuance plan: a job descriptor identity does not match its registry index",
        );
    }

    #[test]
    fn serial_assembly_rejects_swapped_job_references() {
        let mut plan = two_disclosure_plan();
        let entries = object_entries_mut(&mut plan);
        let (first, second) = entries.split_at_mut(1);
        std::mem::swap(
            disclosed_job_id_mut(&mut first[0]),
            disclosed_job_id_mut(&mut second[0]),
        );

        assert_invalid_plan(
            plan,
            "invalid issuance plan: an issuance job was restored at the wrong structural location",
        );
    }

    #[test]
    fn serial_assembly_rejects_out_of_range_tree_job_identity() {
        let mut plan = two_disclosure_plan();
        let out_of_range_job_id = JobId::try_from(plan.jobs.len()).unwrap();
        *disclosed_job_id_mut(&mut object_entries_mut(&mut plan)[0]) = out_of_range_job_id;

        assert_invalid_plan(
            plan,
            "invalid issuance plan: an issuance job identity is out of bounds",
        );
    }

    #[test]
    fn serial_assembly_rejects_mismatched_descriptor_location() {
        let mut plan = two_disclosure_plan();
        plan.jobs[0].location_id = plan.jobs[1].location_id;

        assert_invalid_plan(
            plan,
            "invalid issuance plan: an issuance job was restored at the wrong structural location",
        );
    }

    #[test]
    fn serial_assembly_rejects_duplicate_disclosure_ordinal() {
        let mut plan = two_disclosure_plan();
        let first_ordinal = *disclosure_ordinal_mut(&mut plan.jobs[0]);
        *disclosure_ordinal_mut(&mut plan.jobs[1]) = first_ordinal;

        assert_invalid_plan(
            plan,
            "invalid issuance plan: a disclosure ordinal is bound to the wrong job identity",
        );
    }

    #[test]
    fn serial_assembly_rejects_swapped_disclosure_ordinals() {
        let mut plan = two_disclosure_plan();
        let (first, second) = plan.jobs.split_at_mut(1);
        std::mem::swap(
            disclosure_ordinal_mut(&mut first[0]),
            disclosure_ordinal_mut(&mut second[0]),
        );

        assert_invalid_plan(
            plan,
            "invalid issuance plan: a disclosure ordinal is bound to the wrong job identity",
        );
    }

    #[test]
    fn serial_assembly_rejects_swapped_disclosure_registry_entries() {
        let mut plan = two_disclosure_plan();
        plan.disclosure_job_ids.swap(0, 1);

        assert_invalid_plan(
            plan,
            "invalid issuance plan: a disclosure ordinal is bound to the wrong job identity",
        );
    }

    #[test]
    fn serial_assembly_rejects_out_of_range_disclosure_ordinal() {
        let mut plan = two_disclosure_plan();
        *disclosure_ordinal_mut(&mut plan.jobs[0]) = plan.disclosure_job_ids.len();

        assert_invalid_plan(
            plan,
            "invalid issuance plan: a disclosure ordinal is out of bounds",
        );
    }

    #[test]
    fn serial_assembly_rejects_out_of_range_disclosure_registry_identity() {
        let mut random_source = RecordingRandomSource::with_decoy_counts([]);
        let mut plan = IssuancePlan::create(
            json!({}),
            ClaimsForSelectiveDisclosureStrategy::NoSDClaims,
            false,
            &mut random_source,
        )
        .unwrap();
        plan.disclosure_job_ids.push(0);

        assert_invalid_plan(
            plan,
            "invalid issuance plan: a disclosure job identity is out of bounds",
        );
    }

    #[test]
    fn serial_assembly_rejects_missing_job() {
        let mut plan = two_disclosure_plan();
        match &mut plan.root.kind {
            PlannedValueKind::Object(object) => {
                object.entries.pop();
            }
            _ => panic!("test plan root must be an object"),
        }

        assert_invalid_plan(
            plan,
            "invalid issuance plan: not every issuance job was executed",
        );
    }

    #[test]
    fn serial_executor_assembly_matches_the_serial_oracle_for_nested_claims() {
        let expected = nested_plan(true).execute_serial().unwrap();
        let actual = nested_plan(true)
            .execute_with_executor(&SerialIssuanceExecutor::default())
            .unwrap();

        assert_assemblies_equal(&expected, &actual);
    }

    #[test]
    fn shuffled_completion_order_restores_exact_claim_and_disclosure_bytes() {
        let expected = nested_plan(true).execute_serial().unwrap();
        let actual = nested_plan(true)
            .execute_with_executor(&ShufflingIssuanceExecutor)
            .unwrap();

        assert_assemblies_equal(&expected, &actual);
    }

    #[test]
    fn executor_runs_child_batches_before_their_parent_disclosures() {
        struct RecordingBatchExecutor {
            batches: RefCell<Vec<Vec<JobId>>>,
        }

        impl IssuanceExecutor for RecordingBatchExecutor {
            fn execute(&self, jobs: Vec<IssuanceJob>) -> Result<Vec<IssuanceOutcome>> {
                self.batches
                    .borrow_mut()
                    .push(jobs.iter().map(|job| job.identity.job_id).collect());
                SerialIssuanceExecutor::default().execute(jobs)
            }
        }

        let executor = RecordingBatchExecutor {
            batches: RefCell::new(Vec::new()),
        };
        nested_plan(false).execute_with_executor(&executor).unwrap();

        // A disclosure can include the transformed value of nested
        // disclosures, so only jobs whose child subtree is complete are
        // independent. Sibling jobs at each object/array boundary are batched.
        assert_eq!(
            *executor.batches.borrow(),
            vec![vec![0, 1], vec![3, 4], vec![2, 5, 6]]
        );
    }

    #[test]
    fn executor_rejects_missing_duplicate_misplaced_and_malformed_results() {
        for (mutation, expected_message) in [
            (
                OutcomeMutation::Missing,
                "invalid issuance executor result: a planned issuance result was not returned",
            ),
            (
                OutcomeMutation::Duplicate,
                "invalid issuance executor result: an issuance result identity was returned more than once",
            ),
            (
                OutcomeMutation::Misplaced,
                "invalid issuance executor result: an issuance result was bound to the wrong planned location or kind",
            ),
            (
                OutcomeMutation::MissingWorkerOutput,
                "invalid issuance executor result: an issuance result contained no worker output",
            ),
            (
                OutcomeMutation::WrongResultKind,
                "invalid issuance executor result: an issuance result has the wrong result kind",
            ),
            (
                OutcomeMutation::Unexpected,
                "invalid issuance executor result: an unexpected issuance result identity was returned",
            ),
        ] {
            assert_executor_error(&MutatingIssuanceExecutor(mutation), expected_message);
        }
    }

    #[test]
    fn executor_worker_errors_use_planned_order_after_completion_shuffle() {
        struct ShuffledFailureExecutor;

        impl IssuanceExecutor for ShuffledFailureExecutor {
            fn execute(&self, jobs: Vec<IssuanceJob>) -> Result<Vec<IssuanceOutcome>> {
                let mut outcomes = SerialIssuanceExecutor::default().execute(jobs)?;
                outcomes[0].result = Some(Err(Error::InvalidState(
                    "first planned worker failure".to_owned(),
                )));
                outcomes[1].result = Some(Err(Error::InvalidState(
                    "second planned worker failure".to_owned(),
                )));
                outcomes.reverse();
                Ok(outcomes)
            }
        }

        let error = match two_disclosure_plan().execute_with_executor(&ShuffledFailureExecutor) {
            Ok(_) => panic!("injected worker errors must fail closed"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "invalid state: first planned worker failure"
        );
    }

    #[test]
    fn production_policy_is_the_exact_serial_oracle_until_thresholds_are_qualified() {
        let expected = nested_plan(true).execute_serial().unwrap();
        let actual = nested_plan(true).execute().unwrap();

        assert_assemblies_equal(&expected, &actual);
    }

    #[cfg(all(
        feature = "parallel",
        not(feature = "issuance_bench"),
        target_arch = "x86_64"
    ))]
    #[test]
    fn parallel_feature_alone_does_not_activate_benchmark_routing() {
        assert!(QUALIFIED_ISSUANCE_THRESHOLDS.is_none());
        let expected = nested_plan(true).execute_serial().unwrap();
        let actual = nested_plan(true).execute().unwrap();

        assert_assemblies_equal(&expected, &actual);
    }

    #[test]
    fn fixed_tape_full_credential_is_identical_after_shuffled_job_completion() {
        const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";
        let claims = || {
            json!({
                "iss": "https://issuer.example",
                "iat": 1,
                "exp": 2,
                "profile": { "name": "Alice", "city": "München" },
                "roles": ["admin", "reader"]
            })
        };
        let issuer = || {
            SDJWTIssuer::new(
                EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap(),
                None,
            )
        };

        for serialization_format in [
            crate::SDJWTSerializationFormat::Compact,
            crate::SDJWTSerializationFormat::FlattenedJson,
            crate::SDJWTSerializationFormat::GeneralJson,
        ] {
            let mut serial_random = RecordingRandomSource::with_decoy_counts([2, 3]);
            let mut serial_issuer = issuer();
            let serial = serial_issuer
                .issue_sd_jwt_with_plan_executor(
                    claims(),
                    ClaimsForSelectiveDisclosureStrategy::AllLevels,
                    IssuanceOptions {
                        holder_key: None,
                        add_decoy_claims: true,
                        serialization_format: serialization_format.clone(),
                    },
                    &mut serial_random,
                    IssuancePlan::execute_serial,
                )
                .unwrap();

            let mut shuffled_random = RecordingRandomSource::with_decoy_counts([2, 3]);
            let mut shuffled_issuer = issuer();
            let shuffled = shuffled_issuer
                .issue_sd_jwt_with_plan_executor(
                    claims(),
                    ClaimsForSelectiveDisclosureStrategy::AllLevels,
                    IssuanceOptions {
                        holder_key: None,
                        add_decoy_claims: true,
                        serialization_format,
                    },
                    &mut shuffled_random,
                    |plan| plan.execute_with_executor(&ShufflingIssuanceExecutor),
                )
                .unwrap();

            assert_eq!(shuffled_random.events, serial_random.events);
            assert_eq!(shuffled, serial);
        }
    }

    #[test]
    fn injected_worker_failure_returns_before_signing_or_serialization() {
        struct FailingIssuanceExecutor;

        impl IssuanceExecutor for FailingIssuanceExecutor {
            fn execute(&self, jobs: Vec<IssuanceJob>) -> Result<Vec<IssuanceOutcome>> {
                let mut outcomes = SerialIssuanceExecutor::default().execute(jobs)?;
                outcomes[0].result = Some(Err(Error::InvalidState(
                    "injected issuance worker failure".to_owned(),
                )));
                Ok(outcomes)
            }
        }

        const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";
        let mut issuer = SDJWTIssuer::new(
            EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes()).unwrap(),
            None,
        );
        let mut random_source = RecordingRandomSource::with_decoy_counts([]);

        let error = issuer
            .issue_sd_jwt_with_plan_executor(
                json!({ "name": "Alice", "city": "Denver" }),
                ClaimsForSelectiveDisclosureStrategy::AllLevels,
                IssuanceOptions {
                    holder_key: None,
                    add_decoy_claims: false,
                    serialization_format: crate::SDJWTSerializationFormat::Compact,
                },
                &mut random_source,
                |plan| plan.execute_with_executor(&FailingIssuanceExecutor),
            )
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            "invalid state: injected issuance worker failure"
        );
        assert!(issuer.all_disclosures.is_empty());
        assert!(issuer.sd_jwt_payload.is_empty());
        assert!(issuer.signed_sd_jwt.is_empty());
        assert!(issuer.serialized_sd_jwt.is_empty());
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn native_parallel_executor_matches_serial_after_fixed_tape_planning() {
        let expected = nested_plan(true).execute_serial().unwrap();
        let actual = nested_plan(true)
            .execute_with_executor(&NativeParallelIssuanceExecutor::new(4))
            .unwrap();

        assert_assemblies_equal(&expected, &actual);
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn native_parallel_executor_caps_overlapping_workers() {
        static ACTIVE: TestAtomicUsize = TestAtomicUsize::new(0);
        static MAX_ACTIVE: TestAtomicUsize = TestAtomicUsize::new(0);

        fn observing_worker(job: IssuanceJob) -> IssuanceOutcome {
            let active = ACTIVE.fetch_add(1, TestOrdering::SeqCst) + 1;
            MAX_ACTIVE.fetch_max(active, TestOrdering::SeqCst);
            std::thread::sleep(Duration::from_millis(10));
            let outcome = process_issuance_job(job);
            ACTIVE.fetch_sub(1, TestOrdering::SeqCst);
            outcome
        }

        ACTIVE.store(0, TestOrdering::SeqCst);
        MAX_ACTIVE.store(0, TestOrdering::SeqCst);
        let claims = Value::Object(
            (0..24)
                .map(|ordinal| (format!("claim-{ordinal}"), json!(ordinal)))
                .collect(),
        );
        let mut random_source = RecordingRandomSource::with_decoy_counts([]);
        let plan = IssuancePlan::create(
            claims,
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            false,
            &mut random_source,
        )
        .unwrap();

        plan.execute_with_executor(&NativeParallelIssuanceExecutor::with_worker(
            3,
            observing_worker,
        ))
        .unwrap();

        let maximum = MAX_ACTIVE.load(TestOrdering::SeqCst);
        assert!((2..=3).contains(&maximum), "observed {maximum} workers");
        assert_eq!(ACTIVE.load(TestOrdering::SeqCst), 0);
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn native_parallel_worker_and_spawn_failures_are_generic_and_fail_closed() {
        fn panicking_worker(job: IssuanceJob) -> IssuanceOutcome {
            if job.identity.job_id == 1 {
                panic!("injected worker panic");
            }
            process_issuance_job(job)
        }

        let worker_error = match two_disclosure_plan().execute_with_executor(
            &NativeParallelIssuanceExecutor::with_worker(2, panicking_worker),
        ) {
            Ok(_) => panic!("worker panic must fail closed"),
            Err(error) => error,
        };
        let spawn_error = match two_disclosure_plan().execute_with_executor(
            &NativeParallelIssuanceExecutor::with_forced_spawn_failure(2, 1),
        ) {
            Ok(_) => panic!("spawn failure must fail closed"),
            Err(error) => error,
        };

        for (error, expected) in [
            (worker_error, PARALLEL_ISSUANCE_WORKER_FAILURE),
            (spawn_error, PARALLEL_ISSUANCE_SPAWN_FAILURE),
        ] {
            match error {
                Error::InvalidState(message) => {
                    assert_eq!(message, expected);
                    assert!(!message.contains("job"));
                    assert!(!message.contains("claim"));
                    assert!(!message.contains("ordinal"));
                }
                other => panic!("unexpected native executor error: {other:?}"),
            }
        }
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn ready_job_estimator_accounts_for_each_operation_exactly() {
        let jobs = selector_accounting_jobs();
        let estimates = jobs[..3]
            .iter()
            .map(|job| estimate_ready_job_work_bytes(std::slice::from_ref(job)).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(estimates, [16, 12, 3]);
        assert_eq!(estimate_ready_job_work_bytes(&jobs[..3]), Some(31));
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn selector_and_static_layout_account_for_non_divisible_ready_batch() {
        let jobs = selector_accounting_jobs();
        let job_weights = jobs
            .iter()
            .map(|job| estimate_ready_job_work_bytes(std::slice::from_ref(job)).unwrap())
            .collect::<Vec<_>>();
        let thresholds = IssuancePolicyThresholds {
            min_jobs: 1,
            min_estimated_work_bytes: 1,
        };
        let mode = select_execution_mode(&jobs, thresholds, || 4);
        let IssuanceExecutionMode::NativeParallel { worker_count } = mode else {
            panic!("accounting fixture must select native execution");
        };

        let chunk_size = static_chunk_size(jobs.len(), worker_count);
        let chunk_counts = jobs.chunks(chunk_size).map(<[_]>::len).collect::<Vec<_>>();
        let chunk_loads = jobs
            .chunks(chunk_size)
            .map(|chunk| estimate_ready_job_work_bytes(chunk).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(worker_count, 4);
        assert_eq!(chunk_size, 2);
        assert_eq!(job_weights, [16, 12, 3, 16, 12]);
        assert_eq!(chunk_counts, [2, 2, 1]);
        assert_eq!(chunk_loads, [28, 19, 12]);
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn selector_applies_count_then_work_before_querying_available_parallelism() {
        use std::cell::Cell;

        let jobs = selector_accounting_jobs();
        let available_parallelism_queries = Cell::new(0usize);
        let query_available_parallelism = || {
            available_parallelism_queries.set(available_parallelism_queries.get() + 1);
            4
        };

        assert_eq!(
            select_execution_mode(
                &jobs[..2],
                IssuancePolicyThresholds {
                    min_jobs: 3,
                    min_estimated_work_bytes: 1,
                },
                query_available_parallelism,
            ),
            IssuanceExecutionMode::Serial
        );
        assert_eq!(available_parallelism_queries.get(), 0);

        assert_eq!(
            select_execution_mode(
                &jobs[..3],
                IssuancePolicyThresholds {
                    min_jobs: 3,
                    min_estimated_work_bytes: 32,
                },
                query_available_parallelism,
            ),
            IssuanceExecutionMode::Serial
        );
        assert_eq!(available_parallelism_queries.get(), 0);

        assert_eq!(
            select_execution_mode(
                &jobs,
                IssuancePolicyThresholds {
                    min_jobs: 3,
                    min_estimated_work_bytes: 31,
                },
                query_available_parallelism,
            ),
            IssuanceExecutionMode::NativeParallel { worker_count: 4 }
        );
        assert_eq!(available_parallelism_queries.get(), 1);
    }

    #[cfg(all(
        feature = "issuance_bench",
        feature = "parallel",
        target_arch = "x86_64"
    ))]
    #[test]
    fn benchmark_tracing_is_observational_for_fixed_nested_decoy_plan() {
        let serial = nested_plan(true).execute_serial().unwrap();
        let untraced = nested_plan(true).execute_benchmark_candidate().unwrap();
        let (traced, trace) = nested_plan(true)
            .execute_benchmark_candidate_with_trace()
            .unwrap();

        assert_assemblies_equal(&serial, &untraced);
        assert_assemblies_equal(&serial, &traced);
        assert_eq!(
            trace.executor_batches,
            trace.serial_batches + trace.native_batches
        );
        assert!(trace.executor_batches > 0);
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn adaptive_policy_is_serial_until_qualified_and_obeys_injected_cutoffs() {
        use std::cell::Cell;

        assert!(QUALIFIED_ISSUANCE_THRESHOLDS.is_none());
        let budget = ParallelIssuanceWorkerBudget::new(MAX_PARALLEL_ISSUANCE_WORKERS);
        let expected = two_disclosure_plan().execute_serial().unwrap();
        let thread_queries = Cell::new(0usize);
        let actual = two_disclosure_plan()
            .execute_adaptively(None, &budget, || {
                thread_queries.set(thread_queries.get() + 1);
                MAX_PARALLEL_ISSUANCE_WORKERS
            })
            .unwrap();
        assert_assemblies_equal(&expected, &actual);
        assert_eq!(thread_queries.get(), 0);

        let jobs = policy_jobs(2, 64);
        let thresholds = IssuancePolicyThresholds {
            min_jobs: 2,
            min_estimated_work_bytes: 1,
        };
        assert_eq!(
            select_execution_mode(&jobs, thresholds, || 8),
            IssuanceExecutionMode::NativeParallel { worker_count: 2 }
        );
        assert_eq!(
            select_execution_mode(
                &jobs,
                IssuancePolicyThresholds {
                    min_jobs: 3,
                    min_estimated_work_bytes: 1,
                },
                || 8,
            ),
            IssuanceExecutionMode::Serial
        );
        assert_eq!(
            select_execution_mode(
                &jobs,
                IssuancePolicyThresholds {
                    min_jobs: 2,
                    min_estimated_work_bytes: usize::MAX,
                },
                || 8,
            ),
            IssuanceExecutionMode::Serial
        );
        assert_eq!(
            select_execution_mode(&jobs, thresholds, || 1),
            IssuanceExecutionMode::Serial
        );
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn adaptive_policy_does_not_treat_a_dependent_chain_as_one_parallel_batch() {
        use std::cell::Cell;

        let mut claims = json!("leaf");
        for depth in 0..16 {
            let mut object = Map::new();
            object.insert(format!("level-{depth}"), claims);
            claims = Value::Object(object);
        }
        let mut random_source = RecordingRandomSource::with_decoy_counts([]);
        let plan = IssuancePlan::create(
            claims,
            ClaimsForSelectiveDisclosureStrategy::AllLevels,
            false,
            &mut random_source,
        )
        .unwrap();
        assert_eq!(plan.jobs.len(), 16);

        let budget = ParallelIssuanceWorkerBudget::new(MAX_PARALLEL_ISSUANCE_WORKERS);
        let thread_queries = Cell::new(0usize);
        plan.execute_adaptively(
            Some(IssuancePolicyThresholds {
                min_jobs: 2,
                min_estimated_work_bytes: 1,
            }),
            &budget,
            || {
                thread_queries.set(thread_queries.get() + 1);
                MAX_PARALLEL_ISSUANCE_WORKERS
            },
        )
        .unwrap();

        assert_eq!(thread_queries.get(), 0);
        assert_eq!(budget.available(), MAX_PARALLEL_ISSUANCE_WORKERS);
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn adaptive_worker_lease_is_released_between_ready_batches() {
        use std::cell::Cell;

        let budget = ParallelIssuanceWorkerBudget::new(MAX_PARALLEL_ISSUANCE_WORKERS);
        let thread_queries = Cell::new(0usize);
        nested_plan(false)
            .execute_adaptively(
                Some(IssuancePolicyThresholds {
                    min_jobs: 2,
                    min_estimated_work_bytes: 1,
                }),
                &budget,
                || {
                    assert_eq!(budget.available(), MAX_PARALLEL_ISSUANCE_WORKERS);
                    thread_queries.set(thread_queries.get() + 1);
                    MAX_PARALLEL_ISSUANCE_WORKERS
                },
            )
            .unwrap();

        assert_eq!(thread_queries.get(), 3);
        assert_eq!(budget.available(), MAX_PARALLEL_ISSUANCE_WORKERS);
    }

    #[cfg(all(feature = "parallel", target_arch = "x86_64"))]
    #[test]
    fn adaptive_budget_contention_falls_back_without_overcommitting_workers() {
        let budget = ParallelIssuanceWorkerBudget::new(MAX_PARALLEL_ISSUANCE_WORKERS);
        let held = budget.try_acquire(MAX_PARALLEL_ISSUANCE_WORKERS).unwrap();
        let expected = nested_plan(true).execute_serial().unwrap();
        let actual = nested_plan(true)
            .execute_adaptively(
                Some(IssuancePolicyThresholds {
                    min_jobs: 1,
                    min_estimated_work_bytes: 1,
                }),
                &budget,
                || MAX_PARALLEL_ISSUANCE_WORKERS,
            )
            .unwrap();

        assert_eq!(budget.available(), 0);
        assert_assemblies_equal(&expected, &actual);
        drop(held);
        assert_eq!(budget.available(), MAX_PARALLEL_ISSUANCE_WORKERS);
    }
}
