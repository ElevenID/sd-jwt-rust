// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

//! Opt-in deterministic support for the SD-JWT issuance Criterion benchmark.
//!
//! This module is intentionally compiled only by the `issuance_bench` feature.
//! The public facade is necessary because Cargo compiles a Criterion target as
//! a separate crate; all executor controls behind it remain crate-private.

use std::collections::VecDeque;
use std::ops::Range;

use jsonwebtoken::EncodingKey;
use serde_json::{json, Map, Value};

use super::issuance_plan::{
    BenchmarkBudgetAcquisitionResult, BenchmarkExecutionTraceSummary, BenchmarkReadyBatchTrace,
    BenchmarkSelectedMode, BenchmarkSelectionReason, BenchmarkWorkEstimateStatus, IssuanceAssembly,
    IssuancePlan, BENCHMARK_ISSUANCE_WORKER_CAP, BENCHMARK_STATIC_PARTITION_RULE_VERSION,
    BENCHMARK_WORK_ESTIMATOR_VERSION,
};
use super::{
    ClaimsForSelectiveDisclosureStrategy, IssuanceOptions, IssuanceRandomSource, SDJWTIssuer,
};
use crate::error::{Error, Result};
use crate::SDJWTSerializationFormat;

/// Disclosure counts shared by every required payload class.
pub const ISSUANCE_DISCLOSURE_COUNTS: [usize; 5] = [1, 8, 32, 128, 512];

/// Each large disclosed value contains exactly 64 KiB before JSON encoding.
pub const ISSUANCE_LARGE_PAYLOAD_BYTES: usize = 64 * 1024;

/// Stable Criterion group prefix used in route evidence.
pub const ISSUANCE_BENCHMARK_GROUP_ID: &str = "sd_jwt_issuance";

/// Twenty core cases plus ten focused root/nested-decoy cases.
pub const ISSUANCE_FIXTURE_CASE_COUNT: usize = 30;

/// Two stages times two requested routes for every fixture case.
pub const ISSUANCE_BENCHMARK_ID_COUNT: usize = ISSUANCE_FIXTURE_CASE_COUNT * 2 * 2;

/// Payload shape used by an issuance benchmark fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuancePayloadClass {
    Small,
    Medium,
    Large,
    Mixed,
}

impl IssuancePayloadClass {
    fn label(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Medium => "medium_nested",
            Self::Large => "large_64_kib",
            Self::Mixed => "mixed_nested",
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::Small => "s",
            Self::Medium => "mn",
            Self::Large => "l64",
            Self::Mixed => "mx",
        }
    }

    fn value(self, ordinal: usize) -> Value {
        match self {
            Self::Small => small_value(ordinal),
            Self::Medium => medium_value(ordinal),
            Self::Large => large_value(ordinal),
            Self::Mixed => match ordinal % 3 {
                0 => small_value(ordinal),
                1 => medium_value(ordinal),
                _ => large_value(ordinal),
            },
        }
    }
}

/// Timed portion selected by a benchmark ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuanceBenchmarkStage {
    /// Execute and restore an already-created immutable issuance plan.
    ExecutorAssembly,
    /// Plan, assemble, sign, and serialize one complete compact credential.
    FullIssuance,
}

impl IssuanceBenchmarkStage {
    fn label(self) -> &'static str {
        match self {
            Self::ExecutorAssembly => "executor_assembly",
            Self::FullIssuance => "full_issuance",
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::ExecutorAssembly => "ea",
            Self::FullIssuance => "fi",
        }
    }
}

/// Explicit route requested by a benchmark ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuanceBenchmarkRoute {
    /// Immutable behavioral oracle.
    SerialOracle,
    /// Adaptive selector with mechanical benchmark eligibility.
    AdaptiveCandidate,
}

impl IssuanceBenchmarkRoute {
    fn label(self) -> &'static str {
        match self {
            Self::SerialOracle => "serial_oracle",
            Self::AdaptiveCandidate => "adaptive_candidate",
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::SerialOracle => "so",
            Self::AdaptiveCandidate => "ac",
        }
    }
}

/// Effective route observed during an untimed candidate preflight.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssuanceBenchmarkEffectiveRoute {
    SerialOracle,
    BoundedNative,
    MixedNativeAndSerial,
    ReadyBatchSerialFallback,
    BudgetSerialFallback,
    TargetSerialFallback,
}

impl IssuanceBenchmarkEffectiveRoute {
    fn label(self) -> &'static str {
        match self {
            Self::SerialOracle => "serial_oracle",
            Self::BoundedNative => "bounded_native",
            Self::MixedNativeAndSerial => "mixed_native_and_serial",
            Self::ReadyBatchSerialFallback => "ready_batch_serial_fallback",
            Self::BudgetSerialFallback => "budget_serial_fallback",
            Self::TargetSerialFallback => "target_serial_fallback",
        }
    }
}

/// Stable fixture descriptor. Fields remain private so the matrix can only be
/// constructed through the reviewed generator below.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssuanceBenchmarkCase {
    disclosure_count: usize,
    payload_class: IssuancePayloadClass,
    add_decoy_claims: bool,
}

impl IssuanceBenchmarkCase {
    /// Stable fixture ID independent of host and Criterion configuration.
    pub fn fixture_id(self) -> String {
        format!(
            "payload_{}__decoys_{}__n_{:04}",
            self.payload_class.label(),
            if self.add_decoy_claims { "on" } else { "off" },
            self.disclosure_count
        )
    }

    /// Stable machine-readable Criterion ID, versioned for frozen runners.
    pub fn benchmark_id(
        self,
        stage: IssuanceBenchmarkStage,
        route: IssuanceBenchmarkRoute,
    ) -> String {
        format!(
            "v1__s_{}__r_{}__p_{}__d_{}__n_{:04}",
            stage.code(),
            route.code(),
            self.payload_class.code(),
            usize::from(self.add_decoy_claims),
            self.disclosure_count,
        )
    }
}

/// Return the complete, ordered benchmark matrix.
pub fn issuance_benchmark_cases() -> Vec<IssuanceBenchmarkCase> {
    let payload_classes = [
        IssuancePayloadClass::Small,
        IssuancePayloadClass::Medium,
        IssuancePayloadClass::Large,
        IssuancePayloadClass::Mixed,
    ];
    let mut cases = Vec::with_capacity(ISSUANCE_FIXTURE_CASE_COUNT);

    for payload_class in payload_classes {
        for disclosure_count in ISSUANCE_DISCLOSURE_COUNTS {
            cases.push(IssuanceBenchmarkCase {
                disclosure_count,
                payload_class,
                add_decoy_claims: false,
            });
        }
    }

    // Small isolates root-decoy scheduling cost; mixed exercises decoys in
    // both the root and nested objects without doubling every expensive case.
    for payload_class in [IssuancePayloadClass::Small, IssuancePayloadClass::Mixed] {
        for disclosure_count in ISSUANCE_DISCLOSURE_COUNTS {
            cases.push(IssuanceBenchmarkCase {
                disclosure_count,
                payload_class,
                add_decoy_claims: true,
            });
        }
    }

    debug_assert_eq!(cases.len(), ISSUANCE_FIXTURE_CASE_COUNT);
    cases
}

/// Exact claims and deterministic randomness shared by both requested routes.
pub struct IssuanceBenchmarkFixture {
    case: IssuanceBenchmarkCase,
    selective_claims: Value,
    full_claims: Value,
    random_tape: BenchmarkRandomTape,
    issuer_key: EncodingKey,
    sign_alg: String,
    executor_input_bytes: usize,
    full_input_bytes: usize,
}

impl IssuanceBenchmarkFixture {
    /// Build all expensive input data around an already-parsed signing key.
    pub fn new(
        case: IssuanceBenchmarkCase,
        issuer_key: EncodingKey,
        sign_alg: String,
    ) -> Result<Self> {
        let selective_claims = selective_claims(case);
        let full_claims = full_claims(&selective_claims)?;
        let random_tape = BenchmarkRandomTape::new(&selective_claims, case);
        let executor_input_bytes = serde_json::to_vec(&selective_claims)
            .map_err(|error| Error::InvalidState(format!("invalid benchmark claims: {error}")))?
            .len();
        let full_input_bytes = serde_json::to_vec(&full_claims)
            .map_err(|error| Error::InvalidState(format!("invalid benchmark claims: {error}")))?
            .len();

        Ok(Self {
            case,
            selective_claims,
            full_claims,
            random_tape,
            issuer_key,
            sign_alg,
            executor_input_bytes,
            full_input_bytes,
        })
    }

    /// Serialized input size for the selected timed boundary.
    pub fn input_bytes(&self, stage: IssuanceBenchmarkStage) -> usize {
        match stage {
            IssuanceBenchmarkStage::ExecutorAssembly => self.executor_input_bytes,
            IssuanceBenchmarkStage::FullIssuance => self.full_input_bytes,
        }
    }

    /// Build the immutable plan in Criterion's untimed setup closure.
    pub fn prepare_executor(&self) -> Result<PreparedExecutorBenchmark> {
        let mut random_tape = self.random_tape.clone();
        let plan = IssuancePlan::create(
            self.selective_claims.clone(),
            ClaimsForSelectiveDisclosureStrategy::TopLevel,
            self.case.add_decoy_claims,
            &mut random_tape,
        )?;
        random_tape.finish()?;
        Ok(PreparedExecutorBenchmark { plan })
    }

    /// Clone input state in Criterion's untimed setup closure; planning remains
    /// inside the full-issuance timed path by design.
    pub fn prepare_full_issuance(&self) -> PreparedFullIssuanceBenchmark {
        PreparedFullIssuanceBenchmark {
            claims: self.full_claims.clone(),
            random_tape: self.random_tape.clone(),
            issuer: SDJWTIssuer::new(self.issuer_key.clone(), Some(self.sign_alg.clone())),
            add_decoy_claims: self.case.add_decoy_claims,
        }
    }

    /// Untimed exact-output and route gate run before Criterion registration.
    pub fn preflight(&self) -> Result<IssuanceBenchmarkPreflight> {
        let serial_assembly = self
            .prepare_executor()?
            .execute(IssuanceBenchmarkRoute::SerialOracle)?;
        let (candidate_assembly, candidate_route) =
            self.prepare_executor()?.execute_candidate_with_trace()?;
        if serial_assembly != candidate_assembly {
            return Err(Error::InvalidState(
                "issuance benchmark serial/candidate assembly mismatch".to_owned(),
            ));
        }
        if serial_assembly.disclosure_count() != self.case.disclosure_count {
            return Err(Error::InvalidState(
                "issuance benchmark assembly disclosure count mismatch".to_owned(),
            ));
        }

        let serial_credential = self
            .prepare_full_issuance()
            .execute(IssuanceBenchmarkRoute::SerialOracle)?;
        let (candidate_credential, full_candidate_route) = self
            .prepare_full_issuance()
            .execute_candidate_with_trace()?;
        if serial_credential != candidate_credential {
            return Err(Error::InvalidState(
                "issuance benchmark serial/candidate credential mismatch".to_owned(),
            ));
        }
        if compact_disclosure_count(&serial_credential)? != self.case.disclosure_count {
            return Err(Error::InvalidState(
                "issuance benchmark credential disclosure count mismatch".to_owned(),
            ));
        }

        Ok(IssuanceBenchmarkPreflight {
            executor_candidate_route: candidate_route,
            full_candidate_route,
        })
    }
}

/// Already-created plan used by the executor-only stage.
pub struct PreparedExecutorBenchmark {
    plan: IssuancePlan,
}

impl PreparedExecutorBenchmark {
    /// Execute one requested route. Planning is already complete.
    pub fn execute(self, route: IssuanceBenchmarkRoute) -> Result<IssuanceBenchmarkAssembly> {
        let assembly = match route {
            IssuanceBenchmarkRoute::SerialOracle => self.plan.execute_serial()?,
            IssuanceBenchmarkRoute::AdaptiveCandidate => self.plan.execute_benchmark_candidate()?,
        };
        Ok(IssuanceBenchmarkAssembly::from(assembly))
    }

    fn execute_candidate_with_trace(
        self,
    ) -> Result<(IssuanceBenchmarkAssembly, IssuanceBenchmarkRouteRecord)> {
        let (assembly, summary) = self.plan.execute_benchmark_candidate_with_trace()?;
        Ok((
            IssuanceBenchmarkAssembly::from(assembly),
            IssuanceBenchmarkRouteRecord::candidate(summary),
        ))
    }
}

/// Cloned claims, random tape, and parsed signing key used by full issuance.
pub struct PreparedFullIssuanceBenchmark {
    claims: Value,
    random_tape: BenchmarkRandomTape,
    issuer: SDJWTIssuer,
    add_decoy_claims: bool,
}

impl PreparedFullIssuanceBenchmark {
    /// Plan, assemble, sign, and compact-serialize one credential.
    pub fn execute(mut self, route: IssuanceBenchmarkRoute) -> Result<String> {
        let options = IssuanceOptions {
            holder_key: None,
            add_decoy_claims: self.add_decoy_claims,
            serialization_format: SDJWTSerializationFormat::Compact,
        };
        let credential = match route {
            IssuanceBenchmarkRoute::SerialOracle => self.issuer.issue_sd_jwt_with_plan_executor(
                self.claims,
                ClaimsForSelectiveDisclosureStrategy::TopLevel,
                options,
                &mut self.random_tape,
                IssuancePlan::execute_serial,
            )?,
            IssuanceBenchmarkRoute::AdaptiveCandidate => {
                self.issuer.issue_sd_jwt_with_plan_executor(
                    self.claims,
                    ClaimsForSelectiveDisclosureStrategy::TopLevel,
                    options,
                    &mut self.random_tape,
                    IssuancePlan::execute_benchmark_candidate,
                )?
            }
        };
        self.random_tape.finish()?;
        Ok(credential)
    }

    fn execute_candidate_with_trace(mut self) -> Result<(String, IssuanceBenchmarkRouteRecord)> {
        let options = IssuanceOptions {
            holder_key: None,
            add_decoy_claims: self.add_decoy_claims,
            serialization_format: SDJWTSerializationFormat::Compact,
        };
        let mut trace_summary = None;
        let credential = self.issuer.issue_sd_jwt_with_plan_executor(
            self.claims,
            ClaimsForSelectiveDisclosureStrategy::TopLevel,
            options,
            &mut self.random_tape,
            |plan| {
                let (assembly, summary) = plan.execute_benchmark_candidate_with_trace()?;
                trace_summary = Some(summary);
                Ok(assembly)
            },
        )?;
        self.random_tape.finish()?;
        let summary = trace_summary.ok_or_else(|| {
            Error::InvalidState("full issuance benchmark route was not recorded".to_owned())
        })?;
        Ok((credential, IssuanceBenchmarkRouteRecord::candidate(summary)))
    }
}

/// Comparable executor output with no signing or serialization work.
#[derive(Debug, PartialEq)]
pub struct IssuanceBenchmarkAssembly {
    claims: Value,
    disclosures: Vec<String>,
}

impl IssuanceBenchmarkAssembly {
    /// Number of real disclosures restored in legacy ordinal order.
    pub fn disclosure_count(&self) -> usize {
        self.disclosures.len()
    }
}

impl From<IssuanceAssembly> for IssuanceBenchmarkAssembly {
    fn from(assembly: IssuanceAssembly) -> Self {
        Self {
            claims: assembly.claims,
            disclosures: assembly
                .disclosures
                .into_iter()
                .map(|disclosure| disclosure.raw_b64)
                .collect(),
        }
    }
}

/// Successful untimed equality gate plus observed candidate routing.
pub struct IssuanceBenchmarkPreflight {
    executor_candidate_route: IssuanceBenchmarkRouteRecord,
    full_candidate_route: IssuanceBenchmarkRouteRecord,
}

impl IssuanceBenchmarkPreflight {
    /// Candidate route observed for the already-planned executor stage.
    pub fn executor_candidate_route(&self) -> IssuanceBenchmarkRouteRecord {
        self.executor_candidate_route.clone()
    }

    /// Candidate route observed while running the full issuance boundary.
    pub fn full_candidate_route(&self) -> IssuanceBenchmarkRouteRecord {
        self.full_candidate_route.clone()
    }
}

/// Machine-readable requested/effective route evidence from untimed preflight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuanceBenchmarkRouteRecord {
    requested: IssuanceBenchmarkRoute,
    effective: IssuanceBenchmarkEffectiveRoute,
    executor_batches: Option<usize>,
    serial_batches: Option<usize>,
    native_batches: Option<usize>,
    budget_fallback_batches: Option<usize>,
    max_native_worker_count: usize,
    host_available_parallelism: usize,
    ready_batches: Option<Vec<BenchmarkReadyBatchTrace>>,
}

impl IssuanceBenchmarkRouteRecord {
    /// Route record for the immutable serial oracle.
    pub fn serial_oracle() -> Self {
        Self {
            requested: IssuanceBenchmarkRoute::SerialOracle,
            effective: IssuanceBenchmarkEffectiveRoute::SerialOracle,
            executor_batches: None,
            serial_batches: None,
            native_batches: None,
            budget_fallback_batches: None,
            max_native_worker_count: 0,
            host_available_parallelism: available_parallelism(),
            ready_batches: None,
        }
    }

    fn candidate(summary: BenchmarkExecutionTraceSummary) -> Self {
        assert_eq!(
            summary.target_serial_fallback,
            summary.ready_batches.is_none(),
            "whole-target fallback must be the only candidate route without ready-batch evidence"
        );
        let effective = if summary.target_serial_fallback {
            IssuanceBenchmarkEffectiveRoute::TargetSerialFallback
        } else if summary.native_batches != 0 && summary.serial_batches != 0 {
            IssuanceBenchmarkEffectiveRoute::MixedNativeAndSerial
        } else if summary.native_batches != 0 {
            IssuanceBenchmarkEffectiveRoute::BoundedNative
        } else if summary.budget_fallback_batches != 0 {
            IssuanceBenchmarkEffectiveRoute::BudgetSerialFallback
        } else {
            IssuanceBenchmarkEffectiveRoute::ReadyBatchSerialFallback
        };

        if let Some(ready_batches) = &summary.ready_batches {
            for (ordinal, batch) in ready_batches.iter().enumerate() {
                assert_ready_batch_trace(ordinal, batch);
            }
            let native_batches = ready_batches
                .iter()
                .filter(|batch| batch.selected_mode == BenchmarkSelectedMode::NativeParallel)
                .count();
            let serial_batches = ready_batches.len().saturating_sub(native_batches);
            let budget_fallback_batches = ready_batches
                .iter()
                .filter(|batch| {
                    batch.selection_reason == BenchmarkSelectionReason::WorkerBudgetUnavailable
                })
                .count();
            let max_worker_count = ready_batches
                .iter()
                .filter_map(|batch| batch.leased_worker_count)
                .max()
                .unwrap_or(0);
            assert_eq!(summary.executor_batches, ready_batches.len());
            assert_eq!(summary.serial_batches, serial_batches);
            assert_eq!(summary.native_batches, native_batches);
            assert_eq!(summary.budget_fallback_batches, budget_fallback_batches);
            assert_eq!(summary.max_worker_count, max_worker_count);
        }

        Self {
            requested: IssuanceBenchmarkRoute::AdaptiveCandidate,
            effective,
            executor_batches: (!summary.target_serial_fallback).then_some(summary.executor_batches),
            serial_batches: (!summary.target_serial_fallback).then_some(summary.serial_batches),
            native_batches: (!summary.target_serial_fallback).then_some(summary.native_batches),
            budget_fallback_batches: (!summary.target_serial_fallback)
                .then_some(summary.budget_fallback_batches),
            max_native_worker_count: summary.max_worker_count,
            host_available_parallelism: available_parallelism(),
            ready_batches: summary.ready_batches,
        }
    }

    /// Effective route selected during preflight.
    pub fn effective(self) -> IssuanceBenchmarkEffectiveRoute {
        self.effective
    }

    /// Stable NDJSON-compatible record for a later frozen runner.
    pub fn machine_record(
        self,
        case: IssuanceBenchmarkCase,
        stage: IssuanceBenchmarkStage,
    ) -> String {
        let ready_batches = self.ready_batches.as_ref().map(|batches| {
            batches
                .iter()
                .map(ready_batch_machine_value)
                .collect::<Vec<_>>()
        });
        let record = json!({
            "schema": "sd_jwt_issuance_route_v2",
            "benchmark_id": format!(
                "{}/{}",
                ISSUANCE_BENCHMARK_GROUP_ID,
                case.benchmark_id(stage, self.requested)
            ),
            "fixture_id": case.fixture_id(),
            "stage": stage.label(),
            "requested": self.requested.label(),
            "effective": self.effective.label(),
            "executor_batches": self.executor_batches,
            "serial_batches": self.serial_batches,
            "native_batches": self.native_batches,
            "budget_fallback_batches": self.budget_fallback_batches,
            "max_native_worker_count": self.max_native_worker_count,
            "worker_cap": BENCHMARK_ISSUANCE_WORKER_CAP,
            "host_available_parallelism": self.host_available_parallelism,
            "work_estimator_version": BENCHMARK_WORK_ESTIMATOR_VERSION,
            "static_partition_rule_version": BENCHMARK_STATIC_PARTITION_RULE_VERSION,
            "ready_batches": ready_batches,
        });
        serde_json::to_string(&record).expect("benchmark route record must serialize")
    }
}

fn assert_ready_batch_trace(expected_ordinal: usize, batch: &BenchmarkReadyBatchTrace) {
    assert_eq!(batch.ordinal, expected_ordinal);
    assert_eq!(
        batch.work_gate_evaluated,
        batch.work_estimate_status != BenchmarkWorkEstimateStatus::NotEvaluated
    );
    match batch.work_estimate_status {
        BenchmarkWorkEstimateStatus::NotEvaluated | BenchmarkWorkEstimateStatus::Overflow => {
            assert!(batch.estimated_work_bytes.is_none())
        }
        BenchmarkWorkEstimateStatus::Available => assert!(batch.estimated_work_bytes.is_some()),
    }
    assert_eq!(
        batch.parallelism_gate_evaluated,
        batch.available_parallelism.is_some()
    );
    assert_eq!(
        batch.selected_worker_count,
        batch.available_parallelism.map(|available| {
            available
                .min(BENCHMARK_ISSUANCE_WORKER_CAP)
                .min(batch.job_count)
        })
    );
    assert_eq!(
        batch.budget_gate_evaluated,
        batch.budget_acquisition_result != BenchmarkBudgetAcquisitionResult::NotEvaluated
    );

    match batch.selection_reason {
        BenchmarkSelectionReason::BelowMinJobs => {
            assert_eq!(
                batch.work_estimate_status,
                BenchmarkWorkEstimateStatus::NotEvaluated
            );
            assert!(!batch.parallelism_gate_evaluated);
            assert!(!batch.budget_gate_evaluated);
        }
        BenchmarkSelectionReason::WorkEstimateOverflow => {
            assert_eq!(
                batch.work_estimate_status,
                BenchmarkWorkEstimateStatus::Overflow
            );
            assert!(!batch.parallelism_gate_evaluated);
            assert!(!batch.budget_gate_evaluated);
        }
        BenchmarkSelectionReason::BelowMinEstimatedWorkBytes => {
            assert_eq!(
                batch.work_estimate_status,
                BenchmarkWorkEstimateStatus::Available
            );
            assert!(!batch.parallelism_gate_evaluated);
            assert!(!batch.budget_gate_evaluated);
        }
        BenchmarkSelectionReason::InsufficientAvailableParallelism => {
            assert_eq!(
                batch.work_estimate_status,
                BenchmarkWorkEstimateStatus::Available
            );
            assert!(batch.parallelism_gate_evaluated);
            assert!(!batch.budget_gate_evaluated);
        }
        BenchmarkSelectionReason::WorkerBudgetUnavailable => {
            assert_eq!(
                batch.budget_acquisition_result,
                BenchmarkBudgetAcquisitionResult::Unavailable
            );
        }
        BenchmarkSelectionReason::BoundedNative => {
            assert_eq!(
                batch.budget_acquisition_result,
                BenchmarkBudgetAcquisitionResult::Acquired
            );
        }
    }

    match batch.selected_mode {
        BenchmarkSelectedMode::Serial => {
            assert_ne!(
                batch.selection_reason,
                BenchmarkSelectionReason::BoundedNative
            );
            assert!(batch.leased_worker_count.is_none());
            assert!(batch.static_chunk_size.is_none());
            assert!(batch.static_chunks.is_none());
        }
        BenchmarkSelectedMode::NativeParallel => {
            assert_eq!(
                batch.selection_reason,
                BenchmarkSelectionReason::BoundedNative
            );
            assert_eq!(
                batch.budget_acquisition_result,
                BenchmarkBudgetAcquisitionResult::Acquired
            );
            assert_eq!(batch.leased_worker_count, batch.selected_worker_count);
            let chunk_size = batch
                .static_chunk_size
                .expect("native trace must include its static chunk size");
            let selected_worker_count = batch
                .selected_worker_count
                .expect("native trace must include selected workers");
            assert_eq!(
                chunk_size,
                batch.job_count / selected_worker_count
                    + usize::from(batch.job_count % selected_worker_count != 0)
            );
            let chunks = batch
                .static_chunks
                .as_ref()
                .expect("native trace must include static chunks");
            assert_eq!(
                chunks.iter().map(|chunk| chunk.job_count).sum::<usize>(),
                batch.job_count
            );
            assert_eq!(
                chunks
                    .iter()
                    .map(|chunk| chunk.estimated_work_bytes)
                    .sum::<usize>(),
                batch
                    .estimated_work_bytes
                    .expect("native trace must include a successful work estimate")
            );
            for (ordinal, chunk) in chunks.iter().enumerate() {
                assert_eq!(chunk.ordinal, ordinal);
                assert!(chunk.job_count <= chunk_size);
            }
        }
    }
}

fn ready_batch_machine_value(batch: &BenchmarkReadyBatchTrace) -> Value {
    let static_chunks = batch.static_chunks.as_ref().map(|chunks| {
        chunks
            .iter()
            .map(|chunk| {
                json!({
                    "ordinal": chunk.ordinal,
                    "job_count": chunk.job_count,
                    "estimated_work_bytes": chunk.estimated_work_bytes,
                })
            })
            .collect::<Vec<_>>()
    });
    json!({
        "ordinal": batch.ordinal,
        "job_count": batch.job_count,
        "estimated_work_bytes": batch.estimated_work_bytes,
        "work_estimate_status": batch.work_estimate_status.label(),
        "work_gate_evaluated": batch.work_gate_evaluated,
        "parallelism_gate_evaluated": batch.parallelism_gate_evaluated,
        "budget_gate_evaluated": batch.budget_gate_evaluated,
        "available_parallelism": batch.available_parallelism,
        "selected_worker_count": batch.selected_worker_count,
        "leased_worker_count": batch.leased_worker_count,
        "budget_acquisition_result": batch.budget_acquisition_result.label(),
        "selected_mode": batch.selected_mode.label(),
        "selection_reason": batch.selection_reason.label(),
        "static_chunk_size": batch.static_chunk_size,
        "static_chunks": static_chunks,
    })
}

#[derive(Clone)]
struct BenchmarkRandomTape {
    disclosure_salts: VecDeque<String>,
    decoy_counts: VecDeque<u32>,
    decoy_salts: VecDeque<String>,
}

impl BenchmarkRandomTape {
    fn new(selective_claims: &Value, case: IssuanceBenchmarkCase) -> Self {
        let disclosure_salts = (0..case.disclosure_count)
            .map(|ordinal| deterministic_salt(0x44, ordinal))
            .collect();
        let mut decoy_counts = VecDeque::new();
        let mut decoy_salt_count = 0usize;
        if case.add_decoy_claims {
            for ordinal in 0..object_count(selective_claims) {
                let count = 2 + u32::try_from(ordinal % 3).expect("ordinal remainder fits u32");
                decoy_counts.push_back(count);
                decoy_salt_count = decoy_salt_count.saturating_add(count as usize);
            }
        }
        let decoy_salts = (0..decoy_salt_count)
            .map(|ordinal| deterministic_salt(0x58, ordinal))
            .collect();
        Self {
            disclosure_salts,
            decoy_counts,
            decoy_salts,
        }
    }

    fn finish(&self) -> Result<()> {
        if self.disclosure_salts.is_empty()
            && self.decoy_counts.is_empty()
            && self.decoy_salts.is_empty()
        {
            Ok(())
        } else {
            Err(Error::InvalidState(
                "issuance benchmark random tape was not consumed exactly".to_owned(),
            ))
        }
    }
}

impl IssuanceRandomSource for BenchmarkRandomTape {
    fn disclosure_salt(&mut self) -> String {
        self.disclosure_salts
            .pop_front()
            .expect("issuance benchmark disclosure salt tape exhausted")
    }

    fn decoy_count(&mut self, range: Range<u32>) -> u32 {
        let count = self
            .decoy_counts
            .pop_front()
            .expect("issuance benchmark decoy-count tape exhausted");
        assert!(
            range.contains(&count),
            "issuance benchmark decoy count is outside the issuer range"
        );
        count
    }

    fn decoy_salt(&mut self) -> String {
        self.decoy_salts
            .pop_front()
            .expect("issuance benchmark decoy salt tape exhausted")
    }
}

fn deterministic_salt(domain: u8, ordinal: usize) -> String {
    let mut bytes = (ordinal as u128).to_be_bytes();
    bytes[0] = domain;
    crate::utils::base64url_encode(&bytes)
}

fn selective_claims(case: IssuanceBenchmarkCase) -> Value {
    let mut claims = Map::new();
    for ordinal in 0..case.disclosure_count {
        claims.insert(
            format!("claim_{ordinal:04}"),
            case.payload_class.value(ordinal),
        );
    }
    Value::Object(claims)
}

fn full_claims(selective_claims: &Value) -> Result<Value> {
    let selective_claims = selective_claims
        .as_object()
        .ok_or_else(|| Error::InvalidState("benchmark claims must be an object".to_owned()))?;
    let mut claims = Map::new();
    claims.insert(
        "iss".to_owned(),
        Value::String("https://issuer.example.com".to_owned()),
    );
    claims.insert("iat".to_owned(), Value::from(1_700_000_000_i64));
    claims.extend(selective_claims.clone());
    Ok(Value::Object(claims))
}

fn small_value(ordinal: usize) -> Value {
    Value::String(format!("value-{ordinal}"))
}

fn medium_value(ordinal: usize) -> Value {
    json!({
        "ordinal": ordinal,
        "profile": {
            "active": ordinal % 2 == 0,
            "display_name": format!("Credential subject {ordinal}"),
            "notes": "medium-payload-".repeat(64),
        },
        "roles": ["holder", "member", "verified"],
    })
}

fn large_value(ordinal: usize) -> Value {
    let suffix = format!("-{ordinal}");
    let body_length = ISSUANCE_LARGE_PAYLOAD_BYTES.saturating_sub(suffix.len());
    Value::String(format!("{}{suffix}", "L".repeat(body_length)))
}

fn object_count(value: &Value) -> usize {
    match value {
        Value::Object(values) => 1usize.saturating_add(values.values().map(object_count).sum()),
        Value::Array(values) => values.iter().map(object_count).sum(),
        _ => 0,
    }
}

fn compact_disclosure_count(credential: &str) -> Result<usize> {
    credential
        .split('~')
        .count()
        .checked_sub(2)
        .ok_or_else(|| Error::InvalidState("invalid compact benchmark credential".to_owned()))
}

fn available_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|parallelism| parallelism.get())
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::{Mutex, MutexGuard};

    use super::*;
    use crate::issuer::issuance_plan::BenchmarkStaticChunkTrace;

    static BENCHMARK_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn benchmark_test_guard() -> MutexGuard<'static, ()> {
        BENCHMARK_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn fixture(case: IssuanceBenchmarkCase) -> IssuanceBenchmarkFixture {
        IssuanceBenchmarkFixture::new(
            case,
            EncodingKey::from_secret(b"issuance-benchmark-test-key"),
            "HS256".to_owned(),
        )
        .unwrap()
    }

    #[test]
    fn matrix_cardinality_and_machine_ids_are_stable_and_unique() {
        let cases = issuance_benchmark_cases();
        assert_eq!(cases.len(), ISSUANCE_FIXTURE_CASE_COUNT);
        assert_eq!(
            cases.iter().filter(|case| !case.add_decoy_claims).count(),
            20
        );
        assert_eq!(
            cases.iter().filter(|case| case.add_decoy_claims).count(),
            10
        );

        let mut ids = BTreeSet::new();
        for case in cases {
            for stage in [
                IssuanceBenchmarkStage::ExecutorAssembly,
                IssuanceBenchmarkStage::FullIssuance,
            ] {
                for route in [
                    IssuanceBenchmarkRoute::SerialOracle,
                    IssuanceBenchmarkRoute::AdaptiveCandidate,
                ] {
                    let id = case.benchmark_id(stage, route);
                    assert!(id.is_ascii());
                    assert!(id.starts_with("v1__s_"));
                    assert!(id.len() <= 64);
                    assert!(format!("{ISSUANCE_BENCHMARK_GROUP_ID}/{id}").len() <= 100);
                    assert!(ids.insert(id));
                }
            }
        }
        assert_eq!(ids.len(), ISSUANCE_BENCHMARK_ID_COUNT);
        assert!(ids.contains("v1__s_ea__r_so__p_s__d_0__n_0001"));
        assert!(ids.contains("v1__s_fi__r_ac__p_mx__d_1__n_0512"));

        let case = issuance_benchmark_cases()[0];
        let record = IssuanceBenchmarkRouteRecord::serial_oracle()
            .machine_record(case, IssuanceBenchmarkStage::ExecutorAssembly);
        let record: Value = serde_json::from_str(&record).unwrap();
        assert_eq!(record["schema"], "sd_jwt_issuance_route_v2");
        assert_eq!(
            record["benchmark_id"],
            "sd_jwt_issuance/v1__s_ea__r_so__p_s__d_0__n_0001"
        );
        assert_eq!(
            record["host_available_parallelism"],
            Value::from(
                std::thread::available_parallelism()
                    .map(|parallelism| parallelism.get())
                    .unwrap_or(1)
            )
        );
        assert!(record["executor_batches"].is_null());
        assert!(record["serial_batches"].is_null());
        assert!(record["native_batches"].is_null());
        assert!(record["budget_fallback_batches"].is_null());
        assert!(record["ready_batches"].is_null());

        let target_fallback =
            IssuanceBenchmarkRouteRecord::candidate(BenchmarkExecutionTraceSummary {
                target_serial_fallback: true,
                ..BenchmarkExecutionTraceSummary::default()
            })
            .machine_record(case, IssuanceBenchmarkStage::ExecutorAssembly);
        let target_fallback: Value = serde_json::from_str(&target_fallback).unwrap();
        assert!(target_fallback["executor_batches"].is_null());
        assert!(target_fallback["serial_batches"].is_null());
        assert!(target_fallback["native_batches"].is_null());
        assert!(target_fallback["budget_fallback_batches"].is_null());
        assert!(target_fallback["ready_batches"].is_null());

        let observed_empty =
            IssuanceBenchmarkRouteRecord::candidate(BenchmarkExecutionTraceSummary {
                ready_batches: Some(Vec::new()),
                ..BenchmarkExecutionTraceSummary::default()
            })
            .machine_record(case, IssuanceBenchmarkStage::ExecutorAssembly);
        let observed_empty: Value = serde_json::from_str(&observed_empty).unwrap();
        assert_eq!(observed_empty["ready_batches"], json!([]));
    }

    #[test]
    fn route_v2_exact_schema_snapshot_is_stable() {
        let case = issuance_benchmark_cases()[1];
        let ready_batch = BenchmarkReadyBatchTrace {
            ordinal: 0,
            job_count: 5,
            estimated_work_bytes: Some(59),
            work_estimate_status: BenchmarkWorkEstimateStatus::Available,
            work_gate_evaluated: true,
            parallelism_gate_evaluated: true,
            budget_gate_evaluated: true,
            available_parallelism: Some(12),
            selected_worker_count: Some(4),
            leased_worker_count: Some(4),
            budget_acquisition_result: BenchmarkBudgetAcquisitionResult::Acquired,
            selected_mode: BenchmarkSelectedMode::NativeParallel,
            selection_reason: BenchmarkSelectionReason::BoundedNative,
            static_chunk_size: Some(2),
            static_chunks: Some(vec![
                BenchmarkStaticChunkTrace {
                    ordinal: 0,
                    job_count: 2,
                    estimated_work_bytes: 28,
                },
                BenchmarkStaticChunkTrace {
                    ordinal: 1,
                    job_count: 2,
                    estimated_work_bytes: 19,
                },
                BenchmarkStaticChunkTrace {
                    ordinal: 2,
                    job_count: 1,
                    estimated_work_bytes: 12,
                },
            ]),
        };
        let mut route = IssuanceBenchmarkRouteRecord::candidate(BenchmarkExecutionTraceSummary {
            executor_batches: 1,
            native_batches: 1,
            max_worker_count: 4,
            ready_batches: Some(vec![ready_batch]),
            ..BenchmarkExecutionTraceSummary::default()
        });
        route.host_available_parallelism = 12;

        let actual: Value = serde_json::from_str(
            &route.machine_record(case, IssuanceBenchmarkStage::ExecutorAssembly),
        )
        .unwrap();
        assert_eq!(
            actual,
            json!({
                "schema": "sd_jwt_issuance_route_v2",
                "benchmark_id": "sd_jwt_issuance/v1__s_ea__r_ac__p_s__d_0__n_0008",
                "fixture_id": "payload_small__decoys_off__n_0008",
                "stage": "executor_assembly",
                "requested": "adaptive_candidate",
                "effective": "bounded_native",
                "executor_batches": 1,
                "serial_batches": 0,
                "native_batches": 1,
                "budget_fallback_batches": 0,
                "max_native_worker_count": 4,
                "worker_cap": BENCHMARK_ISSUANCE_WORKER_CAP,
                "host_available_parallelism": 12,
                "work_estimator_version": "issuance_work_bytes_v1",
                "static_partition_rule_version": "contiguous_ceil_chunks_v1",
                "ready_batches": [{
                    "ordinal": 0,
                    "job_count": 5,
                    "estimated_work_bytes": 59,
                    "work_estimate_status": "available",
                    "work_gate_evaluated": true,
                    "parallelism_gate_evaluated": true,
                    "budget_gate_evaluated": true,
                    "available_parallelism": 12,
                    "selected_worker_count": 4,
                    "leased_worker_count": 4,
                    "budget_acquisition_result": "acquired",
                    "selected_mode": "native_parallel",
                    "selection_reason": "bounded_native",
                    "static_chunk_size": 2,
                    "static_chunks": [
                        {"ordinal": 0, "job_count": 2, "estimated_work_bytes": 28},
                        {"ordinal": 1, "job_count": 2, "estimated_work_bytes": 19},
                        {"ordinal": 2, "job_count": 1, "estimated_work_bytes": 12},
                    ],
                }],
            })
        );
    }

    #[test]
    fn route_v2_preserves_explicit_overflow_and_stable_reason_labels() {
        assert_eq!(
            [
                BenchmarkSelectionReason::BelowMinJobs,
                BenchmarkSelectionReason::WorkEstimateOverflow,
                BenchmarkSelectionReason::BelowMinEstimatedWorkBytes,
                BenchmarkSelectionReason::InsufficientAvailableParallelism,
                BenchmarkSelectionReason::WorkerBudgetUnavailable,
                BenchmarkSelectionReason::BoundedNative,
            ]
            .map(BenchmarkSelectionReason::label),
            [
                "below_min_jobs",
                "work_estimate_overflow",
                "below_min_estimated_work_bytes",
                "insufficient_available_parallelism",
                "worker_budget_unavailable",
                "bounded_native",
            ]
        );

        let case = issuance_benchmark_cases()[1];
        let route = IssuanceBenchmarkRouteRecord::candidate(BenchmarkExecutionTraceSummary {
            executor_batches: 1,
            serial_batches: 1,
            ready_batches: Some(vec![BenchmarkReadyBatchTrace {
                ordinal: 0,
                job_count: 8,
                estimated_work_bytes: None,
                work_estimate_status: BenchmarkWorkEstimateStatus::Overflow,
                work_gate_evaluated: true,
                parallelism_gate_evaluated: false,
                budget_gate_evaluated: false,
                available_parallelism: None,
                selected_worker_count: None,
                leased_worker_count: None,
                budget_acquisition_result: BenchmarkBudgetAcquisitionResult::NotEvaluated,
                selected_mode: BenchmarkSelectedMode::Serial,
                selection_reason: BenchmarkSelectionReason::WorkEstimateOverflow,
                static_chunk_size: None,
                static_chunks: None,
            }]),
            ..BenchmarkExecutionTraceSummary::default()
        });
        let record: Value = serde_json::from_str(
            &route.machine_record(case, IssuanceBenchmarkStage::ExecutorAssembly),
        )
        .unwrap();
        assert!(record["ready_batches"][0]["estimated_work_bytes"].is_null());
        assert_eq!(
            record["ready_batches"][0]["work_estimate_status"],
            "overflow"
        );
        assert_eq!(
            record["ready_batches"][0]["selection_reason"],
            "work_estimate_overflow"
        );
    }

    #[test]
    fn route_v2_records_only_aggregate_non_secret_work_metadata() {
        fn collect_keys(value: &Value, keys: &mut BTreeSet<String>) {
            match value {
                Value::Object(values) => {
                    for (key, value) in values {
                        keys.insert(key.clone());
                        collect_keys(value, keys);
                    }
                }
                Value::Array(values) => {
                    for value in values {
                        collect_keys(value, keys);
                    }
                }
                _ => {}
            }
        }

        let _guard = benchmark_test_guard();
        let case = issuance_benchmark_cases()[1];
        let route = fixture(case)
            .prepare_executor()
            .unwrap()
            .execute_candidate_with_trace()
            .unwrap()
            .1;
        let record = route.machine_record(case, IssuanceBenchmarkStage::ExecutorAssembly);
        for forbidden in [
            "claim_0000",
            "value-0",
            "issuance-benchmark-test-key",
            &deterministic_salt(0x44, 0),
        ] {
            assert!(
                !record.contains(forbidden),
                "route evidence leaked {forbidden}"
            );
        }

        let record: Value = serde_json::from_str(&record).unwrap();
        let mut keys = BTreeSet::new();
        collect_keys(&record, &mut keys);
        for forbidden_key in [
            "claim_name",
            "claim_value",
            "salt",
            "job_id",
            "location",
            "location_id",
        ] {
            assert!(!keys.contains(forbidden_key));
        }
    }

    #[test]
    fn deterministic_salts_match_production_encoded_length() {
        assert_eq!(deterministic_salt(0x44, 0).len(), 22);
        assert_eq!(deterministic_salt(0x58, usize::MAX).len(), 22);
        assert_ne!(deterministic_salt(0x44, 7), deterministic_salt(0x58, 7));
    }

    #[test]
    fn serial_and_candidate_outputs_match_for_representative_matrix() {
        let _guard = benchmark_test_guard();
        let representative = issuance_benchmark_cases()
            .into_iter()
            .filter(|case| {
                (case.disclosure_count == 1 || case.disclosure_count == 8)
                    && (!case.add_decoy_claims || case.payload_class == IssuancePayloadClass::Mixed)
            })
            .collect::<Vec<_>>();
        assert_eq!(representative.len(), 10);

        for case in representative {
            let fixture = fixture(case);
            fixture.preflight().unwrap();
        }
    }

    #[test]
    fn mechanical_threshold_keeps_a_one_job_ready_batch_serial() {
        let _guard = benchmark_test_guard();
        let case = issuance_benchmark_cases()
            .into_iter()
            .find(|case| {
                case.disclosure_count == 1
                    && case.payload_class == IssuancePayloadClass::Small
                    && !case.add_decoy_claims
            })
            .unwrap();
        let fixture = fixture(case);
        let preflight = fixture.preflight().unwrap();
        let executor_route = preflight.executor_candidate_route();
        let full_route = preflight.full_candidate_route();

        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(
                executor_route.effective(),
                IssuanceBenchmarkEffectiveRoute::ReadyBatchSerialFallback
            );
            assert_eq!(
                full_route.effective(),
                IssuanceBenchmarkEffectiveRoute::ReadyBatchSerialFallback
            );
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            assert_eq!(
                executor_route.effective(),
                IssuanceBenchmarkEffectiveRoute::TargetSerialFallback
            );
            assert_eq!(
                full_route.effective(),
                IssuanceBenchmarkEffectiveRoute::TargetSerialFallback
            );
        }
    }

    #[test]
    fn eligible_fixture_reaches_the_intended_candidate_route() {
        let _guard = benchmark_test_guard();
        let case = issuance_benchmark_cases()
            .into_iter()
            .find(|case| {
                case.disclosure_count == 8
                    && case.payload_class == IssuancePayloadClass::Small
                    && !case.add_decoy_claims
            })
            .unwrap();
        let preflight = fixture(case).preflight().unwrap();

        for route in [
            preflight.executor_candidate_route(),
            preflight.full_candidate_route(),
        ] {
            #[cfg(target_arch = "x86_64")]
            {
                let selected_available_parallelism = route
                    .ready_batches
                    .as_ref()
                    .and_then(|batches| batches.first())
                    .and_then(|batch| batch.available_parallelism)
                    .unwrap_or(1);
                if selected_available_parallelism >= 2 {
                    assert_eq!(
                        route.effective(),
                        IssuanceBenchmarkEffectiveRoute::BoundedNative
                    );
                } else {
                    assert_eq!(
                        route.effective(),
                        IssuanceBenchmarkEffectiveRoute::ReadyBatchSerialFallback
                    );
                }
            }

            #[cfg(not(target_arch = "x86_64"))]
            assert_eq!(
                route.effective(),
                IssuanceBenchmarkEffectiveRoute::TargetSerialFallback
            );
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[test]
    fn candidate_compiles_and_falls_back_to_serial_on_unsupported_targets() {
        let _guard = benchmark_test_guard();
        let case = issuance_benchmark_cases()[1];
        let fixture = fixture(case);
        let serial = fixture
            .prepare_executor()
            .unwrap()
            .execute(IssuanceBenchmarkRoute::SerialOracle)
            .unwrap();
        let (candidate, route) = fixture
            .prepare_executor()
            .unwrap()
            .execute_candidate_with_trace()
            .unwrap();
        assert_eq!(candidate, serial);
        assert_eq!(
            route.effective(),
            IssuanceBenchmarkEffectiveRoute::TargetSerialFallback
        );
    }
}
