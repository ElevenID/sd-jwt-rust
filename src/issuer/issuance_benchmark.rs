// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

//! Opt-in deterministic support for the SD-JWT issuance Criterion benchmark.
//!
//! This module is intentionally compiled only by the `issuance_bench` feature.
//! The public facade is necessary because Cargo compiles a Criterion target as
//! a separate crate; all executor controls behind it remain crate-private.

use std::collections::{BTreeSet, VecDeque};
use std::env;
use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::ops::Range;
use std::path::PathBuf;

use jsonwebtoken::EncodingKey;
use serde_json::{json, Map, Value};

use super::issuance_plan::{
    benchmark_issuance_policy_facts, BenchmarkBudgetAcquisitionResult,
    BenchmarkExecutionTraceSummary, BenchmarkReadyBatchTrace, BenchmarkSelectedMode,
    BenchmarkSelectionReason, BenchmarkWorkEstimateStatus, IssuanceAssembly, IssuancePlan,
    BENCHMARK_ISSUANCE_WORKER_CAP, BENCHMARK_STATIC_PARTITION_RULE_VERSION,
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

/// Optional absolute create-new destination for aggregate route evidence.
pub const ISSUANCE_ROUTE_NDJSON_ENV: &str = "SD_JWT_ISSUANCE_ROUTE_NDJSON";

const ISSUANCE_ROUTE_SCHEMA: &str = "sd_jwt_issuance_route_v2";
const ISSUANCE_QUALIFICATION_MANIFEST_SCHEMA: &str = "sd_jwt_issuance_qualification_manifest_v1";

/// Twenty core cases, ten focused decoy cases, and three structural cases.
pub const ISSUANCE_FIXTURE_CASE_COUNT: usize = 33;

/// Two stages times two requested routes for every fixture case.
pub const ISSUANCE_BENCHMARK_ID_COUNT: usize = ISSUANCE_FIXTURE_CASE_COUNT * 2 * 2;

/// One serial/candidate pair for each fixture and timed stage.
pub const ISSUANCE_PAIRED_CELL_COUNT: usize = ISSUANCE_FIXTURE_CASE_COUNT * 2;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IssuanceBenchmarkFixtureKind {
    Standard {
        payload_class: IssuancePayloadClass,
        add_decoy_claims: bool,
    },
    AllLevelsNestedObjects,
    AllLevelsArrayDag,
    TopLevelImbalanced,
}

/// Stable fixture descriptor. Fields remain private so the matrix can only be
/// constructed through the reviewed generator below.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IssuanceBenchmarkCase {
    disclosure_count: usize,
    kind: IssuanceBenchmarkFixtureKind,
}

impl IssuanceBenchmarkCase {
    /// Stable fixture ID independent of host and Criterion configuration.
    pub fn fixture_id(self) -> String {
        match self.kind {
            IssuanceBenchmarkFixtureKind::Standard {
                payload_class,
                add_decoy_claims,
            } => format!(
                "payload_{}__decoys_{}__n_{:04}",
                payload_class.label(),
                if add_decoy_claims { "on" } else { "off" },
                self.disclosure_count
            ),
            IssuanceBenchmarkFixtureKind::AllLevelsNestedObjects => {
                "al_nested_obj_n0007".to_owned()
            }
            IssuanceBenchmarkFixtureKind::AllLevelsArrayDag => "al_array_dag_n0008".to_owned(),
            IssuanceBenchmarkFixtureKind::TopLevelImbalanced => "tl_imbalanced_n0008".to_owned(),
        }
    }

    /// Stable machine-readable Criterion ID, versioned for frozen runners.
    pub fn benchmark_id(
        self,
        stage: IssuanceBenchmarkStage,
        route: IssuanceBenchmarkRoute,
    ) -> String {
        match self.kind {
            IssuanceBenchmarkFixtureKind::Standard {
                payload_class,
                add_decoy_claims,
            } => format!(
                "v2__s_{}__r_{}__p_{}__d_{}__n_{:04}",
                stage.code(),
                route.code(),
                payload_class.code(),
                usize::from(add_decoy_claims),
                self.disclosure_count,
            ),
            IssuanceBenchmarkFixtureKind::AllLevelsNestedObjects
            | IssuanceBenchmarkFixtureKind::AllLevelsArrayDag
            | IssuanceBenchmarkFixtureKind::TopLevelImbalanced => format!(
                "v2__s_{}__r_{}__f_{}",
                stage.code(),
                route.code(),
                self.fixture_id(),
            ),
        }
    }

    fn add_decoy_claims(self) -> bool {
        matches!(
            self.kind,
            IssuanceBenchmarkFixtureKind::Standard {
                add_decoy_claims: true,
                ..
            }
        )
    }

    fn disclosure_strategy(self) -> ClaimsForSelectiveDisclosureStrategy<'static> {
        match self.kind {
            IssuanceBenchmarkFixtureKind::AllLevelsNestedObjects
            | IssuanceBenchmarkFixtureKind::AllLevelsArrayDag => {
                ClaimsForSelectiveDisclosureStrategy::AllLevels
            }
            IssuanceBenchmarkFixtureKind::Standard { .. }
            | IssuanceBenchmarkFixtureKind::TopLevelImbalanced => {
                ClaimsForSelectiveDisclosureStrategy::TopLevel
            }
        }
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
                kind: IssuanceBenchmarkFixtureKind::Standard {
                    payload_class,
                    add_decoy_claims: false,
                },
            });
        }
    }

    // Small isolates root-decoy scheduling cost; mixed exercises decoys in
    // both the root and nested objects without doubling every expensive case.
    for payload_class in [IssuancePayloadClass::Small, IssuancePayloadClass::Mixed] {
        for disclosure_count in ISSUANCE_DISCLOSURE_COUNTS {
            cases.push(IssuanceBenchmarkCase {
                disclosure_count,
                kind: IssuanceBenchmarkFixtureKind::Standard {
                    payload_class,
                    add_decoy_claims: true,
                },
            });
        }
    }

    cases.extend([
        IssuanceBenchmarkCase {
            disclosure_count: 7,
            kind: IssuanceBenchmarkFixtureKind::AllLevelsNestedObjects,
        },
        IssuanceBenchmarkCase {
            disclosure_count: 8,
            kind: IssuanceBenchmarkFixtureKind::AllLevelsArrayDag,
        },
        IssuanceBenchmarkCase {
            disclosure_count: 8,
            kind: IssuanceBenchmarkFixtureKind::TopLevelImbalanced,
        },
    ]);

    debug_assert_eq!(cases.len(), ISSUANCE_FIXTURE_CASE_COUNT);
    cases
}

fn full_criterion_id(
    case: IssuanceBenchmarkCase,
    stage: IssuanceBenchmarkStage,
    route: IssuanceBenchmarkRoute,
) -> String {
    format!(
        "{}/{}",
        ISSUANCE_BENCHMARK_GROUP_ID,
        case.benchmark_id(stage, route)
    )
}

fn qualification_criterion_ids(cases: &[IssuanceBenchmarkCase]) -> Vec<String> {
    let mut ids = Vec::with_capacity(ISSUANCE_BENCHMARK_ID_COUNT);
    for case in cases {
        // This is the exact route-then-stage registration order in the
        // Criterion target.
        for route in [
            IssuanceBenchmarkRoute::SerialOracle,
            IssuanceBenchmarkRoute::AdaptiveCandidate,
        ] {
            for stage in [
                IssuanceBenchmarkStage::ExecutorAssembly,
                IssuanceBenchmarkStage::FullIssuance,
            ] {
                ids.push(full_criterion_id(*case, stage, route));
            }
        }
    }
    debug_assert_eq!(ids.len(), ISSUANCE_BENCHMARK_ID_COUNT);
    ids
}

fn qualification_paired_cells(cases: &[IssuanceBenchmarkCase]) -> Vec<Value> {
    let mut cells = Vec::with_capacity(ISSUANCE_PAIRED_CELL_COUNT);
    for case in cases {
        for stage in [
            IssuanceBenchmarkStage::ExecutorAssembly,
            IssuanceBenchmarkStage::FullIssuance,
        ] {
            cells.push(json!({
                "fixture_id": case.fixture_id(),
                "stage": stage.label(),
                "serial_id": full_criterion_id(
                    *case,
                    stage,
                    IssuanceBenchmarkRoute::SerialOracle,
                ),
                "adaptive_id": full_criterion_id(
                    *case,
                    stage,
                    IssuanceBenchmarkRoute::AdaptiveCandidate,
                ),
            }));
        }
    }
    debug_assert_eq!(cells.len(), ISSUANCE_PAIRED_CELL_COUNT);
    cells
}

fn issuance_qualification_manifest_value() -> Value {
    let cases = issuance_benchmark_cases();
    let case_records = cases
        .iter()
        .map(|case| {
            json!({
                "fixture_id": case.fixture_id(),
                "disclosure_count": case.disclosure_count,
            })
        })
        .collect::<Vec<_>>();
    let criterion_ids = qualification_criterion_ids(&cases);
    let paired_cells = qualification_paired_cells(&cases);
    let policy = benchmark_issuance_policy_facts();
    let qualified_issuance_thresholds = match (
        policy.qualified_min_jobs,
        policy.qualified_min_estimated_work_bytes,
    ) {
        (Some(min_jobs), Some(min_estimated_work_bytes)) => json!({
            "min_jobs": min_jobs,
            "min_estimated_work_bytes": min_estimated_work_bytes,
        }),
        (None, None) => Value::Null,
        _ => unreachable!("qualified issuance policy facts must be all present or all absent"),
    };

    json!({
        "schema": ISSUANCE_QUALIFICATION_MANIFEST_SCHEMA,
        "benchmark_group_id": ISSUANCE_BENCHMARK_GROUP_ID,
        "fixture_case_count": ISSUANCE_FIXTURE_CASE_COUNT,
        "benchmark_id_count": ISSUANCE_BENCHMARK_ID_COUNT,
        "paired_cell_count": ISSUANCE_PAIRED_CELL_COUNT,
        "cases": case_records,
        "criterion_ids": criterion_ids,
        "paired_cells": paired_cells,
        "route_schema": ISSUANCE_ROUTE_SCHEMA,
        "work_estimator_version": BENCHMARK_WORK_ESTIMATOR_VERSION,
        "static_partition_rule_version": BENCHMARK_STATIC_PARTITION_RULE_VERSION,
        "worker_cap": BENCHMARK_ISSUANCE_WORKER_CAP,
        "mechanical_benchmark_thresholds": {
            "min_jobs": policy.mechanical_min_jobs,
            "min_estimated_work_bytes": policy.mechanical_min_estimated_work_bytes,
        },
        "qualified_issuance_thresholds": qualified_issuance_thresholds,
    })
}

/// Canonical qualification matrix and policy facts for a frozen benchmark
/// runner. The returned UTF-8 JSON is deterministic, BOM-less, and terminated
/// by exactly one line feed.
pub fn issuance_qualification_manifest_json() -> String {
    let mut manifest = serde_json::to_string_pretty(&issuance_qualification_manifest_value())
        .expect("issuance qualification manifest must serialize");
    manifest.push('\n');
    manifest
}

/// A create-new destination reserved before Criterion starts measuring.
///
/// Holding the reserved write-only file handle does not add work to any timed
/// closure. A process that exits before [`Self::finish`] leaves an empty file,
/// which a qualification controller must reject rather than mistake for
/// complete evidence.
#[derive(Debug)]
pub struct IssuanceBenchmarkRouteSink {
    file: File,
}

impl IssuanceBenchmarkRouteSink {
    /// Validate all route records and durably write one LF-terminated JSON
    /// object per line.
    pub fn finish(mut self, records: &[String]) -> io::Result<()> {
        let payload = validated_route_payload(records)?;
        self.file.write_all(&payload)?;
        self.file.flush()?;
        self.file.sync_all()
    }
}

/// Reserve the optional route-evidence file named by
/// [`ISSUANCE_ROUTE_NDJSON_ENV`].
///
/// The environment variable may be absent. When present, it must contain an
/// absolute path that does not already exist; existing evidence is never
/// replaced.
pub fn prepare_issuance_route_sink_from_env() -> io::Result<Option<IssuanceBenchmarkRouteSink>> {
    prepare_issuance_route_sink(env::var_os(ISSUANCE_ROUTE_NDJSON_ENV))
}

fn prepare_issuance_route_sink(
    destination: Option<OsString>,
) -> io::Result<Option<IssuanceBenchmarkRouteSink>> {
    let Some(destination) = destination else {
        return Ok(None);
    };
    let destination = PathBuf::from(destination);
    if !destination.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "issuance route evidence destination must be absolute",
        ));
    }

    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    Ok(Some(IssuanceBenchmarkRouteSink { file }))
}

fn validated_route_payload(records: &[String]) -> io::Result<Vec<u8>> {
    if records.len() != ISSUANCE_BENCHMARK_ID_COUNT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "issuance route evidence must contain exactly {ISSUANCE_BENCHMARK_ID_COUNT} records"
            ),
        ));
    }

    let expected_ids = qualification_criterion_ids(&issuance_benchmark_cases())
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut observed_ids = BTreeSet::new();
    let mut payload = Vec::with_capacity(records.iter().map(|record| record.len() + 1).sum());

    for record in records {
        if record.contains('\r') || record.contains('\n') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "issuance route record must occupy exactly one line",
            ));
        }
        let value: Value = serde_json::from_str(record).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "issuance route record must be valid JSON",
            )
        })?;
        if value.get("schema").and_then(Value::as_str) != Some(ISSUANCE_ROUTE_SCHEMA) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "issuance route record has an unexpected schema",
            ));
        }
        let benchmark_id = value
            .get("benchmark_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "issuance route record is missing its benchmark ID",
                )
            })?;
        if !observed_ids.insert(benchmark_id.to_owned()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "issuance route evidence contains a duplicate benchmark ID",
            ));
        }

        payload.extend_from_slice(record.as_bytes());
        payload.push(b'\n');
    }

    if observed_ids != expected_ids {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "issuance route evidence does not cover the canonical benchmark IDs",
        ));
    }
    Ok(payload)
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
            self.case.disclosure_strategy(),
            self.case.add_decoy_claims(),
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
            case: self.case,
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

    #[cfg(all(test, target_arch = "x86_64"))]
    fn execute_candidate_with_isolated_trace(
        self,
        available_parallelism: usize,
    ) -> Result<(IssuanceBenchmarkAssembly, IssuanceBenchmarkRouteRecord)> {
        let (assembly, summary) = self
            .plan
            .execute_benchmark_candidate_with_isolated_trace(available_parallelism)?;
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
    case: IssuanceBenchmarkCase,
}

impl PreparedFullIssuanceBenchmark {
    /// Plan, assemble, sign, and compact-serialize one credential.
    pub fn execute(mut self, route: IssuanceBenchmarkRoute) -> Result<String> {
        let options = IssuanceOptions {
            holder_key: None,
            add_decoy_claims: self.case.add_decoy_claims(),
            serialization_format: SDJWTSerializationFormat::Compact,
        };
        let credential = match route {
            IssuanceBenchmarkRoute::SerialOracle => self.issuer.issue_sd_jwt_with_plan_executor(
                self.claims,
                self.case.disclosure_strategy(),
                options,
                &mut self.random_tape,
                IssuancePlan::execute_serial,
            )?,
            IssuanceBenchmarkRoute::AdaptiveCandidate => {
                self.issuer.issue_sd_jwt_with_plan_executor(
                    self.claims,
                    self.case.disclosure_strategy(),
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
            add_decoy_claims: self.case.add_decoy_claims(),
            serialization_format: SDJWTSerializationFormat::Compact,
        };
        let mut trace_summary = None;
        let credential = self.issuer.issue_sd_jwt_with_plan_executor(
            self.claims,
            self.case.disclosure_strategy(),
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

    #[cfg(all(test, target_arch = "x86_64"))]
    fn execute_candidate_with_isolated_trace(
        mut self,
        available_parallelism: usize,
    ) -> Result<(String, IssuanceBenchmarkRouteRecord)> {
        let options = IssuanceOptions {
            holder_key: None,
            add_decoy_claims: self.case.add_decoy_claims(),
            serialization_format: SDJWTSerializationFormat::Compact,
        };
        let mut trace_summary = None;
        let credential = self.issuer.issue_sd_jwt_with_plan_executor(
            self.claims,
            self.case.disclosure_strategy(),
            options,
            &mut self.random_tape,
            |plan| {
                let (assembly, summary) =
                    plan.execute_benchmark_candidate_with_isolated_trace(available_parallelism)?;
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
            "schema": ISSUANCE_ROUTE_SCHEMA,
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
        if case.add_decoy_claims() {
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
    match case.kind {
        IssuanceBenchmarkFixtureKind::Standard { payload_class, .. } => {
            let mut claims = Map::new();
            for ordinal in 0..case.disclosure_count {
                claims.insert(format!("claim_{ordinal:04}"), payload_class.value(ordinal));
            }
            Value::Object(claims)
        }
        IssuanceBenchmarkFixtureKind::AllLevelsNestedObjects => all_levels_nested_object_claims(),
        IssuanceBenchmarkFixtureKind::AllLevelsArrayDag => all_levels_array_dag_claims(),
        IssuanceBenchmarkFixtureKind::TopLevelImbalanced => top_level_imbalanced_claims(),
    }
}

fn all_levels_nested_object_claims() -> Value {
    fn two_scalar_claims(first: &str, second: &str) -> Value {
        let mut claims = Map::new();
        claims.insert(first.to_owned(), Value::String("x".to_owned()));
        claims.insert(second.to_owned(), Value::String("x".to_owned()));
        Value::Object(claims)
    }

    let mut claims = Map::new();
    claims.insert("left".to_owned(), two_scalar_claims("a", "b"));
    claims.insert("right".to_owned(), two_scalar_claims("c", "d"));
    claims.insert("tail".to_owned(), Value::String("x".to_owned()));
    Value::Object(claims)
}

fn all_levels_array_dag_claims() -> Value {
    fn two_scalar_entries() -> Value {
        Value::Array(vec![
            Value::String("x".to_owned()),
            Value::String("x".to_owned()),
        ])
    }

    let groups = Value::Array(vec![two_scalar_entries(), two_scalar_entries()]);
    let mut claims = Map::new();
    claims.insert("groups".to_owned(), groups);
    claims.insert("tag".to_owned(), Value::String("x".to_owned()));
    Value::Object(claims)
}

fn top_level_imbalanced_claims() -> Value {
    let mut claims = Map::new();
    // Explicit insertion is part of this fixture's contract: contiguous
    // static chunks must see both deliberately heavy jobs next to each other.
    claims.insert("h0".to_owned(), Value::String("H".repeat(4 * 1024)));
    claims.insert("h1".to_owned(), Value::String("H".repeat(4 * 1024)));
    for ordinal in 0..6 {
        claims.insert(format!("s{ordinal}"), Value::String(String::new()));
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Mutex, MutexGuard};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::issuer::issuance_plan::BenchmarkStaticChunkTrace;

    static BENCHMARK_TEST_LOCK: Mutex<()> = Mutex::new(());
    static NEXT_ROUTE_PATH: AtomicUsize = AtomicUsize::new(0);

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

    fn structural_case(kind: IssuanceBenchmarkFixtureKind) -> IssuanceBenchmarkCase {
        issuance_benchmark_cases()
            .into_iter()
            .find(|case| case.kind == kind)
            .expect("structural benchmark case must be registered")
    }

    fn structural_cases() -> [IssuanceBenchmarkCase; 3] {
        [
            structural_case(IssuanceBenchmarkFixtureKind::AllLevelsNestedObjects),
            structural_case(IssuanceBenchmarkFixtureKind::AllLevelsArrayDag),
            structural_case(IssuanceBenchmarkFixtureKind::TopLevelImbalanced),
        ]
    }

    #[cfg(target_arch = "x86_64")]
    fn structural_job_weights(case: IssuanceBenchmarkCase) -> Vec<Vec<usize>> {
        match case.kind {
            IssuanceBenchmarkFixtureKind::AllLevelsNestedObjects => {
                vec![vec![36, 36], vec![36, 36], vec![137, 138, 39]]
            }
            IssuanceBenchmarkFixtureKind::AllLevelsArrayDag => {
                vec![vec![31, 31], vec![31, 31], vec![137, 137], vec![147, 38]]
            }
            IssuanceBenchmarkFixtureKind::TopLevelImbalanced => {
                vec![vec![4132, 4132, 36, 36, 36, 36, 36, 36]]
            }
            IssuanceBenchmarkFixtureKind::Standard { .. } => {
                panic!("standard case has no structural weight contract")
            }
        }
    }

    fn unique_route_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock must follow the Unix epoch")
            .as_nanos();
        env::temp_dir().join(format!(
            "sd-jwt-issuance-{label}-{}-{nonce}-{}.ndjson",
            std::process::id(),
            NEXT_ROUTE_PATH.fetch_add(1, Ordering::Relaxed),
        ))
    }

    fn minimal_route_records() -> Vec<String> {
        qualification_criterion_ids(&issuance_benchmark_cases())
            .into_iter()
            .map(|benchmark_id| {
                serde_json::to_string(&json!({
                    "schema": ISSUANCE_ROUTE_SCHEMA,
                    "benchmark_id": benchmark_id,
                }))
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn route_sink_is_optional_and_rejects_relative_destinations() {
        assert!(prepare_issuance_route_sink(None).unwrap().is_none());

        let error =
            prepare_issuance_route_sink(Some(OsString::from("relative.ndjson"))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn route_sink_creates_once_and_writes_the_exact_canonical_id_set() {
        let destination = unique_route_path("valid");
        let records = minimal_route_records();
        let sink = prepare_issuance_route_sink(Some(destination.clone().into_os_string()))
            .unwrap()
            .unwrap();
        sink.finish(&records).unwrap();

        let bytes = std::fs::read(&destination).unwrap();
        assert!(!bytes.starts_with(&[0xef, 0xbb, 0xbf]));
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert!(!bytes.contains(&b'\r'));
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            format!("{}\n", records.join("\n"))
        );

        let error =
            prepare_issuance_route_sink(Some(destination.clone().into_os_string())).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        std::fs::remove_file(destination).unwrap();
    }

    #[test]
    fn route_sink_rejects_incomplete_ambiguous_or_wrong_id_evidence_before_writing() {
        let records = minimal_route_records();
        let invalid_sets = [
            records[..records.len() - 1].to_vec(),
            {
                let mut multiline = records.clone();
                multiline[0].push('\n');
                multiline
            },
            {
                let mut duplicate = records.clone();
                duplicate[0] = duplicate[1].clone();
                duplicate
            },
            {
                let mut wrong_schema = records.clone();
                wrong_schema[0] = serde_json::to_string(&json!({
                    "schema": "sd_jwt_issuance_route_unknown",
                    "benchmark_id": qualification_criterion_ids(&issuance_benchmark_cases())[0],
                }))
                .unwrap();
                wrong_schema
            },
        ];

        for (ordinal, invalid) in invalid_sets.into_iter().enumerate() {
            let destination = unique_route_path(&format!("invalid-{ordinal}"));
            let sink = prepare_issuance_route_sink(Some(destination.clone().into_os_string()))
                .unwrap()
                .unwrap();
            let error = sink.finish(&invalid).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(std::fs::read(&destination).unwrap().is_empty());
            std::fs::remove_file(destination).unwrap();
        }
    }

    #[test]
    fn qualification_manifest_schema_order_and_policy_facts_are_exact() {
        let encoded = issuance_qualification_manifest_json();
        assert!(encoded.starts_with('{'));
        assert!(!encoded.starts_with('\u{feff}'));
        assert!(encoded.ends_with('\n'));
        assert!(!encoded.ends_with("\n\n"));
        assert!(!encoded.contains('\r'));
        assert_eq!(encoded, issuance_qualification_manifest_json());

        let manifest: Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(
            manifest
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "schema",
                "benchmark_group_id",
                "fixture_case_count",
                "benchmark_id_count",
                "paired_cell_count",
                "cases",
                "criterion_ids",
                "paired_cells",
                "route_schema",
                "work_estimator_version",
                "static_partition_rule_version",
                "worker_cap",
                "mechanical_benchmark_thresholds",
                "qualified_issuance_thresholds",
            ]
        );
        assert_eq!(
            manifest["schema"],
            "sd_jwt_issuance_qualification_manifest_v1"
        );
        assert_eq!(manifest["benchmark_group_id"], "sd_jwt_issuance");
        assert_eq!(manifest["fixture_case_count"], 33);
        assert_eq!(manifest["benchmark_id_count"], 132);
        assert_eq!(manifest["paired_cell_count"], 66);
        assert_eq!(manifest["route_schema"], "sd_jwt_issuance_route_v2");
        assert_eq!(manifest["work_estimator_version"], "issuance_work_bytes_v1");
        assert_eq!(
            manifest["static_partition_rule_version"],
            "contiguous_ceil_chunks_v1"
        );
        assert_eq!(manifest["worker_cap"], BENCHMARK_ISSUANCE_WORKER_CAP);
        assert_eq!(
            manifest["mechanical_benchmark_thresholds"],
            json!({"min_jobs": 2, "min_estimated_work_bytes": 1})
        );
        assert!(manifest["qualified_issuance_thresholds"].is_null());

        let cases = manifest["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 33);
        assert_eq!(
            cases[0],
            json!({
                "fixture_id": "payload_small__decoys_off__n_0001",
                "disclosure_count": 1,
            })
        );
        assert_eq!(
            cases[32],
            json!({
                "fixture_id": "tl_imbalanced_n0008",
                "disclosure_count": 8,
            })
        );
        assert!(cases.iter().all(|case| {
            case.as_object()
                .map(|case| {
                    case.keys().map(String::as_str).collect::<Vec<_>>()
                        == ["fixture_id", "disclosure_count"]
                })
                .unwrap_or(false)
        }));

        let criterion_ids = manifest["criterion_ids"].as_array().unwrap();
        assert_eq!(criterion_ids.len(), 132);
        assert_eq!(
            &criterion_ids[..4],
            &[
                json!("sd_jwt_issuance/v2__s_ea__r_so__p_s__d_0__n_0001"),
                json!("sd_jwt_issuance/v2__s_fi__r_so__p_s__d_0__n_0001"),
                json!("sd_jwt_issuance/v2__s_ea__r_ac__p_s__d_0__n_0001"),
                json!("sd_jwt_issuance/v2__s_fi__r_ac__p_s__d_0__n_0001"),
            ]
        );
        assert_eq!(
            &criterion_ids[128..],
            &[
                json!("sd_jwt_issuance/v2__s_ea__r_so__f_tl_imbalanced_n0008"),
                json!("sd_jwt_issuance/v2__s_fi__r_so__f_tl_imbalanced_n0008"),
                json!("sd_jwt_issuance/v2__s_ea__r_ac__f_tl_imbalanced_n0008"),
                json!("sd_jwt_issuance/v2__s_fi__r_ac__f_tl_imbalanced_n0008"),
            ]
        );
        let unique_ids = criterion_ids
            .iter()
            .map(|id| id.as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(unique_ids.len(), 132);

        let paired_cells = manifest["paired_cells"].as_array().unwrap();
        assert_eq!(paired_cells.len(), 66);
        assert_eq!(
            paired_cells[0],
            json!({
                "fixture_id": "payload_small__decoys_off__n_0001",
                "stage": "executor_assembly",
                "serial_id": "sd_jwt_issuance/v2__s_ea__r_so__p_s__d_0__n_0001",
                "adaptive_id": "sd_jwt_issuance/v2__s_ea__r_ac__p_s__d_0__n_0001",
            })
        );
        assert_eq!(
            paired_cells[65],
            json!({
                "fixture_id": "tl_imbalanced_n0008",
                "stage": "full_issuance",
                "serial_id": "sd_jwt_issuance/v2__s_fi__r_so__f_tl_imbalanced_n0008",
                "adaptive_id": "sd_jwt_issuance/v2__s_fi__r_ac__f_tl_imbalanced_n0008",
            })
        );
        let mut unique_cells = BTreeSet::new();
        for cell in paired_cells {
            let cell = cell.as_object().unwrap();
            assert_eq!(
                cell.keys().map(String::as_str).collect::<Vec<_>>(),
                ["fixture_id", "stage", "serial_id", "adaptive_id"]
            );
            assert!(unique_cells.insert((
                cell["fixture_id"].as_str().unwrap(),
                cell["stage"].as_str().unwrap(),
            )));
            assert!(unique_ids.contains(cell["serial_id"].as_str().unwrap()));
            assert!(unique_ids.contains(cell["adaptive_id"].as_str().unwrap()));
        }
        assert_eq!(unique_cells.len(), 66);

        let mut roundtrip = serde_json::to_string_pretty(&manifest).unwrap();
        roundtrip.push('\n');
        assert_eq!(roundtrip, encoded);
    }

    #[test]
    fn matrix_cardinality_and_machine_ids_are_stable_and_unique() {
        assert_eq!(ISSUANCE_FIXTURE_CASE_COUNT, 33);
        assert_eq!(ISSUANCE_BENCHMARK_ID_COUNT, 132);
        let cases = issuance_benchmark_cases();
        assert_eq!(cases.len(), ISSUANCE_FIXTURE_CASE_COUNT);
        assert_eq!(
            cases
                .iter()
                .filter(|case| matches!(
                    case.kind,
                    IssuanceBenchmarkFixtureKind::Standard {
                        add_decoy_claims: false,
                        ..
                    }
                ))
                .count(),
            20
        );
        assert_eq!(
            cases
                .iter()
                .filter(|case| matches!(
                    case.kind,
                    IssuanceBenchmarkFixtureKind::Standard {
                        add_decoy_claims: true,
                        ..
                    }
                ))
                .count(),
            10
        );
        assert_eq!(
            cases
                .iter()
                .filter(|case| !matches!(case.kind, IssuanceBenchmarkFixtureKind::Standard { .. }))
                .count(),
            3
        );
        assert_eq!(
            cases
                .iter()
                .map(|case| case.fixture_id())
                .skip(30)
                .collect::<Vec<_>>(),
            [
                "al_nested_obj_n0007",
                "al_array_dag_n0008",
                "tl_imbalanced_n0008",
            ]
        );
        let fixture_ids = cases
            .iter()
            .map(|case| case.fixture_id())
            .collect::<BTreeSet<_>>();
        assert_eq!(fixture_ids.len(), ISSUANCE_FIXTURE_CASE_COUNT);

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
                    assert!(id.starts_with("v2__s_"));
                    assert!(id.len() <= 64);
                    assert!(format!("{ISSUANCE_BENCHMARK_GROUP_ID}/{id}").len() <= 100);
                    assert!(ids.insert(id));
                }
            }
        }
        assert_eq!(ids.len(), ISSUANCE_BENCHMARK_ID_COUNT);
        assert!(ids.contains("v2__s_ea__r_so__p_s__d_0__n_0001"));
        assert!(ids.contains("v2__s_fi__r_ac__p_mx__d_1__n_0512"));
        assert!(ids.contains("v2__s_fi__r_ac__f_al_nested_obj_n0007"));
        assert!(ids.contains("v2__s_fi__r_ac__f_al_array_dag_n0008"));
        assert!(ids.contains("v2__s_fi__r_ac__f_tl_imbalanced_n0008"));

        let case = issuance_benchmark_cases()[0];
        let record = IssuanceBenchmarkRouteRecord::serial_oracle()
            .machine_record(case, IssuanceBenchmarkStage::ExecutorAssembly);
        let record: Value = serde_json::from_str(&record).unwrap();
        assert_eq!(record["schema"], "sd_jwt_issuance_route_v2");
        assert_eq!(
            record["benchmark_id"],
            "sd_jwt_issuance/v2__s_ea__r_so__p_s__d_0__n_0001"
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
    fn structural_fixture_topologies_and_strategies_are_exact() {
        let nested = structural_case(IssuanceBenchmarkFixtureKind::AllLevelsNestedObjects);
        assert!(matches!(
            nested.disclosure_strategy(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels
        ));
        assert!(!nested.add_decoy_claims());
        let nested = selective_claims(nested);
        let nested = nested.as_object().unwrap();
        assert_eq!(
            nested.keys().map(String::as_str).collect::<Vec<_>>(),
            ["left", "right", "tail"]
        );
        for (key, expected_keys) in [("left", ["a", "b"]), ("right", ["c", "d"])] {
            let child = nested[key].as_object().unwrap();
            assert_eq!(
                child.keys().map(String::as_str).collect::<Vec<_>>(),
                expected_keys
            );
            assert!(child.values().all(|value| value == "x"));
        }
        assert_eq!(nested["tail"], "x");

        let array = structural_case(IssuanceBenchmarkFixtureKind::AllLevelsArrayDag);
        assert!(matches!(
            array.disclosure_strategy(),
            ClaimsForSelectiveDisclosureStrategy::AllLevels
        ));
        assert!(!array.add_decoy_claims());
        let array = selective_claims(array);
        let array = array.as_object().unwrap();
        assert_eq!(
            array.keys().map(String::as_str).collect::<Vec<_>>(),
            ["groups", "tag"]
        );
        let groups = array["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        for leaf in groups {
            assert_eq!(leaf, &json!(["x", "x"]));
        }
        assert_eq!(array["tag"], "x");

        let imbalanced = structural_case(IssuanceBenchmarkFixtureKind::TopLevelImbalanced);
        assert!(matches!(
            imbalanced.disclosure_strategy(),
            ClaimsForSelectiveDisclosureStrategy::TopLevel
        ));
        assert!(!imbalanced.add_decoy_claims());
        let imbalanced = selective_claims(imbalanced);
        let imbalanced = imbalanced.as_object().unwrap();
        assert_eq!(
            imbalanced.keys().map(String::as_str).collect::<Vec<_>>(),
            ["h0", "h1", "s0", "s1", "s2", "s3", "s4", "s5"]
        );
        assert_eq!(imbalanced["h0"].as_str().unwrap().len(), 4 * 1024);
        assert_eq!(imbalanced["h1"].as_str().unwrap().len(), 4 * 1024);
        assert!(imbalanced
            .values()
            .skip(2)
            .all(|value| value.as_str() == Some("")));
    }

    #[test]
    fn structural_preflight_preserves_exact_serial_candidate_equivalence() {
        let _guard = benchmark_test_guard();
        for case in structural_cases() {
            let fixture = fixture(case);

            let serial_assembly = fixture
                .prepare_executor()
                .unwrap()
                .execute(IssuanceBenchmarkRoute::SerialOracle)
                .unwrap();
            let candidate_assembly = fixture
                .prepare_executor()
                .unwrap()
                .execute(IssuanceBenchmarkRoute::AdaptiveCandidate)
                .unwrap();
            assert_eq!(candidate_assembly, serial_assembly);
            assert_eq!(candidate_assembly.disclosure_count(), case.disclosure_count);

            let serial_credential = fixture
                .prepare_full_issuance()
                .execute(IssuanceBenchmarkRoute::SerialOracle)
                .unwrap();
            let candidate_credential = fixture
                .prepare_full_issuance()
                .execute(IssuanceBenchmarkRoute::AdaptiveCandidate)
                .unwrap();
            assert_eq!(candidate_credential, serial_credential);
            assert_eq!(
                compact_disclosure_count(&candidate_credential).unwrap(),
                case.disclosure_count
            );

            fixture.preflight().unwrap();
        }
    }

    #[test]
    fn structural_route_records_preserve_target_specific_null_semantics() {
        let _guard = benchmark_test_guard();
        for case in structural_cases() {
            let preflight = fixture(case).preflight().unwrap();
            for (stage, candidate) in [
                (
                    IssuanceBenchmarkStage::ExecutorAssembly,
                    preflight.executor_candidate_route(),
                ),
                (
                    IssuanceBenchmarkStage::FullIssuance,
                    preflight.full_candidate_route(),
                ),
            ] {
                let serial: Value = serde_json::from_str(
                    &IssuanceBenchmarkRouteRecord::serial_oracle().machine_record(case, stage),
                )
                .unwrap();
                for key in [
                    "executor_batches",
                    "serial_batches",
                    "native_batches",
                    "budget_fallback_batches",
                    "ready_batches",
                ] {
                    assert!(serial[key].is_null(), "serial {key} must be null");
                }

                let candidate: Value =
                    serde_json::from_str(&candidate.machine_record(case, stage)).unwrap();
                assert_eq!(candidate["schema"], "sd_jwt_issuance_route_v2");
                assert_eq!(
                    candidate["work_estimator_version"],
                    "issuance_work_bytes_v1"
                );
                assert_eq!(
                    candidate["static_partition_rule_version"],
                    "contiguous_ceil_chunks_v1"
                );
                #[cfg(target_arch = "x86_64")]
                {
                    assert!(candidate["executor_batches"].is_number());
                    assert!(candidate["serial_batches"].is_number());
                    assert!(candidate["native_batches"].is_number());
                    assert!(candidate["budget_fallback_batches"].is_number());
                    assert!(candidate["ready_batches"].is_array());
                }
                #[cfg(not(target_arch = "x86_64"))]
                for key in [
                    "executor_batches",
                    "serial_batches",
                    "native_batches",
                    "budget_fallback_batches",
                    "ready_batches",
                ] {
                    assert!(
                        candidate[key].is_null(),
                        "target fallback {key} must be null"
                    );
                }
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn structural_ready_batches_and_injected_static_layouts_are_exact() {
        let _guard = benchmark_test_guard();
        for case in structural_cases() {
            let expected_batches = structural_job_weights(case);
            for available_parallelism in [1, 2, 3, 4, 8] {
                let fixture = fixture(case);
                let serial_assembly = fixture
                    .prepare_executor()
                    .unwrap()
                    .execute(IssuanceBenchmarkRoute::SerialOracle)
                    .unwrap();
                let (candidate_assembly, executor_route) = fixture
                    .prepare_executor()
                    .unwrap()
                    .execute_candidate_with_isolated_trace(available_parallelism)
                    .unwrap();
                assert_eq!(candidate_assembly, serial_assembly);

                let serial_credential = fixture
                    .prepare_full_issuance()
                    .execute(IssuanceBenchmarkRoute::SerialOracle)
                    .unwrap();
                let (candidate_credential, full_route) = fixture
                    .prepare_full_issuance()
                    .execute_candidate_with_isolated_trace(available_parallelism)
                    .unwrap();
                assert_eq!(candidate_credential, serial_credential);

                for route in [executor_route, full_route] {
                    assert_eq!(route.executor_batches, Some(expected_batches.len()));
                    assert_eq!(route.budget_fallback_batches, Some(0));
                    if available_parallelism < 2 {
                        assert_eq!(
                            route.effective,
                            IssuanceBenchmarkEffectiveRoute::ReadyBatchSerialFallback
                        );
                        assert_eq!(route.serial_batches, Some(expected_batches.len()));
                        assert_eq!(route.native_batches, Some(0));
                        assert_eq!(route.max_native_worker_count, 0);
                    } else {
                        assert_eq!(
                            route.effective,
                            IssuanceBenchmarkEffectiveRoute::BoundedNative
                        );
                        assert_eq!(route.serial_batches, Some(0));
                        assert_eq!(route.native_batches, Some(expected_batches.len()));
                        assert_eq!(
                            route.max_native_worker_count,
                            expected_batches
                                .iter()
                                .map(|weights| {
                                    available_parallelism
                                        .min(BENCHMARK_ISSUANCE_WORKER_CAP)
                                        .min(weights.len())
                                })
                                .max()
                                .unwrap_or(0)
                        );
                    }

                    let batches = route
                        .ready_batches
                        .as_ref()
                        .expect("x86_64 adaptive execution must record ready batches");
                    assert_eq!(batches.len(), expected_batches.len());

                    for (batch, expected_weights) in batches.iter().zip(&expected_batches) {
                        assert_eq!(batch.job_count, expected_weights.len());
                        assert_eq!(
                            batch.estimated_work_bytes,
                            Some(expected_weights.iter().sum())
                        );
                        assert_eq!(
                            batch.work_estimate_status,
                            BenchmarkWorkEstimateStatus::Available
                        );
                        assert!(batch.work_gate_evaluated);
                        assert!(batch.parallelism_gate_evaluated);
                        assert_eq!(batch.available_parallelism, Some(available_parallelism));

                        let selected_workers = available_parallelism
                            .min(BENCHMARK_ISSUANCE_WORKER_CAP)
                            .min(expected_weights.len());
                        assert_eq!(batch.selected_worker_count, Some(selected_workers));

                        if selected_workers < 2 {
                            assert_eq!(batch.selected_mode, BenchmarkSelectedMode::Serial);
                            assert_eq!(
                                batch.selection_reason,
                                BenchmarkSelectionReason::InsufficientAvailableParallelism
                            );
                            assert!(!batch.budget_gate_evaluated);
                            assert_eq!(
                                batch.budget_acquisition_result,
                                BenchmarkBudgetAcquisitionResult::NotEvaluated
                            );
                            assert!(batch.leased_worker_count.is_none());
                            assert!(batch.static_chunk_size.is_none());
                            assert!(batch.static_chunks.is_none());
                            continue;
                        }

                        assert_eq!(batch.selected_mode, BenchmarkSelectedMode::NativeParallel);
                        assert_eq!(
                            batch.selection_reason,
                            BenchmarkSelectionReason::BoundedNative
                        );
                        assert!(batch.budget_gate_evaluated);
                        assert_eq!(
                            batch.budget_acquisition_result,
                            BenchmarkBudgetAcquisitionResult::Acquired
                        );
                        assert_eq!(batch.leased_worker_count, Some(selected_workers));
                        let chunk_size = expected_weights.len() / selected_workers
                            + usize::from(expected_weights.len() % selected_workers != 0);
                        assert_eq!(batch.static_chunk_size, Some(chunk_size));
                        let expected_chunks = expected_weights
                            .chunks(chunk_size)
                            .enumerate()
                            .map(|(ordinal, weights)| BenchmarkStaticChunkTrace {
                                ordinal,
                                job_count: weights.len(),
                                estimated_work_bytes: weights.iter().sum(),
                            })
                            .collect::<Vec<_>>();
                        assert_eq!(batch.static_chunks.as_ref(), Some(&expected_chunks));
                    }
                }
            }
        }
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
                "benchmark_id": "sd_jwt_issuance/v2__s_ea__r_ac__p_s__d_0__n_0008",
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
            .filter(|case| match case.kind {
                IssuanceBenchmarkFixtureKind::Standard {
                    payload_class,
                    add_decoy_claims,
                } => {
                    (case.disclosure_count == 1 || case.disclosure_count == 8)
                        && (!add_decoy_claims || payload_class == IssuancePayloadClass::Mixed)
                }
                _ => false,
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
            .find(|case| match case.kind {
                IssuanceBenchmarkFixtureKind::Standard {
                    payload_class,
                    add_decoy_claims,
                } => {
                    case.disclosure_count == 1
                        && payload_class == IssuancePayloadClass::Small
                        && !add_decoy_claims
                }
                _ => false,
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
            .find(|case| match case.kind {
                IssuanceBenchmarkFixtureKind::Standard {
                    payload_class,
                    add_decoy_claims,
                } => {
                    case.disclosure_count == 8
                        && payload_class == IssuancePayloadClass::Small
                        && !add_decoy_claims
                }
                _ => false,
            })
            .unwrap();
        let preflight = fixture(case).preflight().unwrap();

        for route in [
            preflight.executor_candidate_route(),
            preflight.full_candidate_route(),
        ] {
            #[cfg(target_arch = "x86_64")]
            {
                let batch = route
                    .ready_batches
                    .as_ref()
                    .and_then(|batches| batches.first())
                    .expect("eligible x86_64 fixture must record its ready batch");
                let selected_available_parallelism = batch.available_parallelism.unwrap_or(1);
                if selected_available_parallelism >= 2 {
                    match route.effective {
                        IssuanceBenchmarkEffectiveRoute::BoundedNative => {
                            assert_eq!(batch.selected_mode, BenchmarkSelectedMode::NativeParallel);
                            assert_eq!(
                                batch.selection_reason,
                                BenchmarkSelectionReason::BoundedNative
                            );
                        }
                        IssuanceBenchmarkEffectiveRoute::BudgetSerialFallback => {
                            assert_eq!(batch.selected_mode, BenchmarkSelectedMode::Serial);
                            assert_eq!(
                                batch.selection_reason,
                                BenchmarkSelectionReason::WorkerBudgetUnavailable
                            );
                        }
                        other => panic!("unexpected eligible candidate route: {other:?}"),
                    }
                } else {
                    assert_eq!(
                        route.effective,
                        IssuanceBenchmarkEffectiveRoute::ReadyBatchSerialFallback
                    );
                    assert_eq!(
                        batch.selection_reason,
                        BenchmarkSelectionReason::InsufficientAvailableParallelism
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
