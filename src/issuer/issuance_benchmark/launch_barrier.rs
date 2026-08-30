// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

//! Frozen child side of the Marty SD-JWT issuance launch barrier.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    issuance_benchmark_cases, qualification_paired_cells, qualification_routes,
    validate_issuance_route_invocation, IssuanceBenchmarkRoute, ISSUANCE_ROUTE_BENCHMARK_ID_ENV,
    ISSUANCE_ROUTE_NDJSON_ENV,
};

/// Optional path to the frozen, controller-created launch token.
pub const MARTY_PERF_START_BARRIER_ENV: &str = "MARTY_PERF_START_BARRIER";

const CRITERION_HOME_ENV: &str = "CRITERION_HOME";
const NO_COLOR_ENV: &str = "NO_COLOR";
const RUST_BACKTRACE_ENV: &str = "RUST_BACKTRACE";
const TEMP_ENV: &str = "TEMP";
const TMP_ENV: &str = "TMP";
const SYSTEM_ROOT_ENV: &str = "SystemRoot";
const WINDIR_ENV: &str = "WINDIR";

const TOKEN_SCHEMA: &str = "marty.performance/sd-jwt-issuance-launch-token/v1";
const READY_SCHEMA: &str = "marty.performance/sd-jwt-issuance-launch-ready/v1";
const RELEASE_SCHEMA: &str = "marty.performance/sd-jwt-issuance-launch-release/v1";
const RECEIPT_SCHEMA: &str = "marty.performance/sd-jwt-issuance-launch-receipt/v1";

/// Frozen v3 cap for a launch ready or release frame, including its LF.
pub const MAX_LAUNCH_FRAME_BYTES: usize = 64 * 1024;

/// Frozen v3 fallback cap for barrier JSON without its own dedicated cap.
pub const MAX_BARRIER_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;

/// Frozen v3 aggregate build-input cap, also bounding the fixed executable.
pub const MAX_FIXED_BINARY_BYTES: u64 = 2_147_483_648;

const MAX_GLOBAL_ROUNDS: u32 = 20;
const MAX_CELLS: u32 = 66;
const MAX_EXPANSION_POSITIONS: u32 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SuperblockOrder {
    AbbaFirst,
    BaabFirst,
}

const SUPERBLOCK_ORDERS: [SuperblockOrder; 20] = [
    SuperblockOrder::AbbaFirst,
    SuperblockOrder::BaabFirst,
    SuperblockOrder::BaabFirst,
    SuperblockOrder::AbbaFirst,
    SuperblockOrder::BaabFirst,
    SuperblockOrder::AbbaFirst,
    SuperblockOrder::AbbaFirst,
    SuperblockOrder::BaabFirst,
    SuperblockOrder::AbbaFirst,
    SuperblockOrder::BaabFirst,
    SuperblockOrder::BaabFirst,
    SuperblockOrder::AbbaFirst,
    SuperblockOrder::AbbaFirst,
    SuperblockOrder::BaabFirst,
    SuperblockOrder::BaabFirst,
    SuperblockOrder::AbbaFirst,
    SuperblockOrder::BaabFirst,
    SuperblockOrder::AbbaFirst,
    SuperblockOrder::BaabFirst,
    SuperblockOrder::AbbaFirst,
];

const ABBA_EXPANSION: [IssuanceBenchmarkRoute; 8] = [
    IssuanceBenchmarkRoute::SerialOracle,
    IssuanceBenchmarkRoute::AdaptiveCandidate,
    IssuanceBenchmarkRoute::AdaptiveCandidate,
    IssuanceBenchmarkRoute::SerialOracle,
    IssuanceBenchmarkRoute::AdaptiveCandidate,
    IssuanceBenchmarkRoute::SerialOracle,
    IssuanceBenchmarkRoute::SerialOracle,
    IssuanceBenchmarkRoute::AdaptiveCandidate,
];

const BAAB_EXPANSION: [IssuanceBenchmarkRoute; 8] = [
    IssuanceBenchmarkRoute::AdaptiveCandidate,
    IssuanceBenchmarkRoute::SerialOracle,
    IssuanceBenchmarkRoute::SerialOracle,
    IssuanceBenchmarkRoute::AdaptiveCandidate,
    IssuanceBenchmarkRoute::SerialOracle,
    IssuanceBenchmarkRoute::AdaptiveCandidate,
    IssuanceBenchmarkRoute::AdaptiveCandidate,
    IssuanceBenchmarkRoute::SerialOracle,
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactFingerprint {
    sha256: String,
    byte_length: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LaunchToken {
    schema: String,
    campaign_id: String,
    global_round_ordinal: u32,
    cell_ordinal: u32,
    expansion_position: u32,
    timing_process_id: String,
    nonce_uppercase_hex_256: String,
    process_identity_pseudonym: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LaunchReadyFrame {
    schema: String,
    campaign_id: String,
    global_round_ordinal: u32,
    cell_ordinal: u32,
    expansion_position: u32,
    timing_process_id: String,
    process_identity_pseudonym: String,
    launch_token_fingerprint: ArtifactFingerprint,
    fixed_binary_fingerprint: ArtifactFingerprint,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LaunchReleaseFrame {
    schema: String,
    campaign_id: String,
    global_round_ordinal: u32,
    cell_ordinal: u32,
    expansion_position: u32,
    timing_process_id: String,
    process_identity_pseudonym: String,
    launch_token_fingerprint: ArtifactFingerprint,
    ready_frame_fingerprint: ArtifactFingerprint,
    process_start_record_fingerprint: ArtifactFingerprint,
    prepared_at_utc_rfc3339_nanoseconds: String,
    prepared_at_monotonic_nanoseconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LaunchReceipt {
    schema: String,
    campaign_id: String,
    global_round_ordinal: u32,
    cell_ordinal: u32,
    expansion_position: u32,
    timing_process_id: String,
    process_identity_pseudonym: String,
    launch_token_fingerprint: ArtifactFingerprint,
    ready_frame_fingerprint: ArtifactFingerprint,
    release_frame_fingerprint: ArtifactFingerprint,
    process_start_record_fingerprint: ArtifactFingerprint,
    fixed_binary_fingerprint: ArtifactFingerprint,
}

#[derive(Debug)]
struct PreparedLaunchBarrier {
    token: LaunchToken,
    token_fingerprint: ArtifactFingerprint,
    fixed_binary_fingerprint: ArtifactFingerprint,
    ready_bytes: Vec<u8>,
    ready_fingerprint: ArtifactFingerprint,
    campaign_root: PathBuf,
    criterion_home: PathBuf,
    route_path: PathBuf,
    temp_path: PathBuf,
    receipt_path: PathBuf,
}

/// Run the optional frozen launch barrier before Criterion is constructed.
///
/// When `MARTY_PERF_START_BARRIER` is absent this is an ordinary benchmark
/// invocation and no standard stream or filesystem operation is performed.
/// When it is present, every error is returned before Criterion construction.
/// The selected full benchmark ID must equal the route scheduled for the
/// token coordinate by the frozen 20-round ABBA/BAAB expansion.
///
/// The frozen controller is the trusted, exclusive owner of the campaign
/// root and must keep its directory ancestry quiescent from spawn through
/// child exit. The child rejects static links/reparse points and revalidates
/// mutable paths after release, but these checks are not a filesystem sandbox
/// against a concurrent actor replacing an ordinary parent directory between
/// two path operations. Any such mutation violates the trusted-controller
/// assumption and invalidates the campaign operationally; detecting it is
/// outside this child-side guarantee.
pub fn run_issuance_launch_barrier_from_env() -> io::Result<()> {
    let Some(prepared) = prepare_from_environment()? else {
        return Ok(());
    };

    // Allocate and lock both standard streams before the ready frame. After
    // the flush succeeds, the blocking read is deliberately the next child
    // protocol operation.
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let stdin = io::stdin();
    let mut stdin = stdin.lock();
    let mut release_bytes = Vec::with_capacity(MAX_LAUNCH_FRAME_BYTES + 1);

    stdout
        .write_all(&prepared.ready_bytes)
        .map_err(|_| protocol_error("launch ready frame write failed"))?;
    stdout
        .flush()
        .map_err(|_| protocol_error("launch ready frame flush failed"))?;

    (&mut stdin)
        .take((MAX_LAUNCH_FRAME_BYTES + 1) as u64)
        .read_to_end(&mut release_bytes)
        .map_err(|_| protocol_error("launch release frame read failed"))?;

    complete_after_release(prepared, &release_bytes)
}

fn prepare_from_environment() -> io::Result<Option<PreparedLaunchBarrier>> {
    let Some(token_path) = env::var_os(MARTY_PERF_START_BARRIER_ENV) else {
        return Ok(None);
    };

    validate_environment_allowlist()?;

    let campaign_root = env::current_dir()
        .map_err(|_| protocol_error("launch working directory is unavailable"))?;
    if !campaign_root.is_absolute() {
        return Err(protocol_error("launch working directory is invalid"));
    }
    require_directory(&campaign_root, "launch working directory is invalid")?;

    let token_path = path_from_utf8_os_string(token_path, "launch token path is not UTF-8")?;
    let token_bytes = read_bounded_regular_file(
        &token_path,
        MAX_BARRIER_ARTIFACT_BYTES,
        "launch token is unavailable",
    )?;
    let token: LaunchToken = parse_canonical_pretty_json(&token_bytes, "launch token is invalid")?;
    validate_token(&token)?;

    let coordinate_stem = coordinate_stem(&token);
    let barriers_directory = require_campaign_directory(
        &campaign_root,
        "barriers",
        "launch token directory is unavailable",
    )?;
    let expected_token_path = barriers_directory.join(format!("{coordinate_stem}.token"));
    require_exact_absolute_path(
        &token_path,
        &expected_token_path,
        "launch token path is invalid",
    )?;

    let criterion_home = required_utf8_path_env(CRITERION_HOME_ENV)?;
    let route_path = required_utf8_path_env(ISSUANCE_ROUTE_NDJSON_ENV)?;
    let temp_path = required_utf8_path_env(TEMP_ENV)?;
    let tmp_path = required_utf8_path_env(TMP_ENV)?;

    let criterion_directory = require_campaign_directory(
        &campaign_root,
        "criterion",
        "Criterion parent directory is unavailable",
    )?;
    let routes_directory = require_campaign_directory(
        &campaign_root,
        "routes",
        "issuance route directory is unavailable",
    )?;
    let temp_directory = require_campaign_directory(
        &campaign_root,
        "tmp",
        "temporary parent directory is unavailable",
    )?;
    require_exact_absolute_path(
        &criterion_home,
        &criterion_directory.join(&coordinate_stem),
        "Criterion home path is invalid",
    )?;
    require_exact_absolute_path(
        &route_path,
        &routes_directory.join(format!("{coordinate_stem}.ndjson")),
        "issuance route path is invalid",
    )?;
    let expected_temp_path = temp_directory.join(&coordinate_stem);
    require_exact_absolute_path(&temp_path, &expected_temp_path, "temporary path is invalid")?;
    require_exact_absolute_path(&tmp_path, &expected_temp_path, "temporary path is invalid")?;

    require_directory(&criterion_home, "Criterion home is unavailable")?;
    require_empty_directory(&criterion_home, "Criterion home is not empty")?;
    require_directory(&temp_path, "temporary directory is unavailable")?;
    require_path_absent(&route_path, "issuance route destination already exists")?;
    let receipt_directory = require_campaign_directory(
        &campaign_root,
        "barrier-receipts",
        "launch receipt directory is unavailable",
    )?;
    let receipt_path = receipt_directory.join(format!("{coordinate_stem}.json"));
    require_path_absent(&receipt_path, "launch receipt already exists")?;

    validate_selected_invocation(&route_path, &token)?;
    validate_literal_environment()?;
    validate_platform_environment()?;

    let current_executable = env::current_exe()
        .map_err(|_| protocol_error("fixed benchmark executable is unavailable"))?;
    let binary_directory = require_campaign_directory(
        &campaign_root,
        "bin",
        "fixed benchmark executable directory is unavailable",
    )?;
    let expected_executable = binary_directory.join(fixed_binary_name());
    require_same_canonical_path(
        &current_executable,
        &expected_executable,
        "fixed benchmark executable path is invalid",
    )?;

    let fixed_binary_fingerprint = fingerprint_regular_file(
        &expected_executable,
        "fixed benchmark executable fingerprint failed",
    )?;
    let token_fingerprint = fingerprint_bytes(&token_bytes)?;
    let ready = LaunchReadyFrame {
        schema: READY_SCHEMA.to_owned(),
        campaign_id: token.campaign_id.clone(),
        global_round_ordinal: token.global_round_ordinal,
        cell_ordinal: token.cell_ordinal,
        expansion_position: token.expansion_position,
        timing_process_id: token.timing_process_id.clone(),
        process_identity_pseudonym: token.process_identity_pseudonym.clone(),
        launch_token_fingerprint: token_fingerprint.clone(),
        fixed_binary_fingerprint: fixed_binary_fingerprint.clone(),
    };
    let ready_bytes = canonical_compact_json(&ready, "launch ready frame encoding failed")?;
    if ready_bytes.len() > MAX_LAUNCH_FRAME_BYTES {
        return Err(protocol_error("launch ready frame exceeds the size limit"));
    }
    let ready_fingerprint = fingerprint_bytes(&ready_bytes)?;

    Ok(Some(PreparedLaunchBarrier {
        token,
        token_fingerprint,
        fixed_binary_fingerprint,
        ready_bytes,
        ready_fingerprint,
        campaign_root,
        criterion_home,
        route_path,
        temp_path,
        receipt_path,
    }))
}

fn complete_after_release(prepared: PreparedLaunchBarrier, release_bytes: &[u8]) -> io::Result<()> {
    if release_bytes.len() > MAX_LAUNCH_FRAME_BYTES {
        return Err(protocol_error(
            "launch release frame exceeds the size limit",
        ));
    }
    let release: LaunchReleaseFrame =
        parse_canonical_compact_json(release_bytes, "launch release frame is invalid")?;
    validate_release(&prepared, &release)?;
    validate_mutable_paths_after_release(&prepared)?;
    let release_fingerprint = fingerprint_bytes(release_bytes)?;

    let receipt = LaunchReceipt {
        schema: RECEIPT_SCHEMA.to_owned(),
        campaign_id: prepared.token.campaign_id,
        global_round_ordinal: prepared.token.global_round_ordinal,
        cell_ordinal: prepared.token.cell_ordinal,
        expansion_position: prepared.token.expansion_position,
        timing_process_id: prepared.token.timing_process_id,
        process_identity_pseudonym: prepared.token.process_identity_pseudonym,
        launch_token_fingerprint: prepared.token_fingerprint,
        ready_frame_fingerprint: prepared.ready_fingerprint,
        release_frame_fingerprint: release_fingerprint,
        process_start_record_fingerprint: release.process_start_record_fingerprint,
        fixed_binary_fingerprint: prepared.fixed_binary_fingerprint,
    };
    let receipt_bytes = canonical_pretty_json(&receipt, "launch receipt encoding failed")?;
    if receipt_bytes.len() > MAX_BARRIER_ARTIFACT_BYTES {
        return Err(protocol_error("launch receipt exceeds the size limit"));
    }
    create_new_durable_file(&prepared.receipt_path, &receipt_bytes)
}

fn validate_environment_allowlist() -> io::Result<()> {
    let mut observed = env::vars_os()
        .map(|(name, _)| {
            name.into_string()
                .map_err(|_| protocol_error("launch environment name is not UTF-8"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    observed.sort_unstable();

    let mut expected = vec![
        CRITERION_HOME_ENV,
        MARTY_PERF_START_BARRIER_ENV,
        NO_COLOR_ENV,
        RUST_BACKTRACE_ENV,
        ISSUANCE_ROUTE_BENCHMARK_ID_ENV,
        ISSUANCE_ROUTE_NDJSON_ENV,
        TEMP_ENV,
        TMP_ENV,
    ];
    if cfg!(windows) {
        expected.extend([SYSTEM_ROOT_ENV, WINDIR_ENV]);
    }
    expected.sort_unstable();

    if observed.iter().map(String::as_str).ne(expected) {
        return Err(protocol_error(
            "launch environment is not the frozen allowlist",
        ));
    }
    Ok(())
}

fn validate_literal_environment() -> io::Result<()> {
    if env::var_os(NO_COLOR_ENV).as_deref() != Some(OsStr::new("1"))
        || env::var_os(RUST_BACKTRACE_ENV).as_deref() != Some(OsStr::new("0"))
    {
        return Err(protocol_error("launch literal environment is invalid"));
    }
    Ok(())
}

fn validate_platform_environment() -> io::Result<()> {
    if cfg!(windows) {
        let system_root = required_utf8_path_env(SYSTEM_ROOT_ENV)?;
        let windir = required_utf8_path_env(WINDIR_ENV)?;
        if !system_root.is_absolute() || system_root != windir {
            return Err(protocol_error("Windows runtime environment is invalid"));
        }
    } else if env::var_os(SYSTEM_ROOT_ENV).is_some() || env::var_os(WINDIR_ENV).is_some() {
        return Err(protocol_error("platform environment is invalid"));
    }
    Ok(())
}

fn require_campaign_directory(
    campaign_root: &Path,
    role: &str,
    message: &'static str,
) -> io::Result<PathBuf> {
    let path = campaign_root.join(role);
    require_directory(&path, message)?;
    Ok(path)
}

fn validate_mutable_paths_after_release(prepared: &PreparedLaunchBarrier) -> io::Result<()> {
    require_directory(
        &prepared.campaign_root,
        "launch working directory is invalid",
    )?;
    require_campaign_directory(
        &prepared.campaign_root,
        "criterion",
        "Criterion parent directory is unavailable",
    )?;
    require_directory(&prepared.criterion_home, "Criterion home is unavailable")?;
    require_empty_directory(&prepared.criterion_home, "Criterion home is not empty")?;
    require_campaign_directory(
        &prepared.campaign_root,
        "routes",
        "issuance route directory is unavailable",
    )?;
    require_path_absent(
        &prepared.route_path,
        "issuance route destination already exists",
    )?;
    require_campaign_directory(
        &prepared.campaign_root,
        "tmp",
        "temporary parent directory is unavailable",
    )?;
    require_directory(&prepared.temp_path, "temporary directory is unavailable")?;
    require_campaign_directory(
        &prepared.campaign_root,
        "barrier-receipts",
        "launch receipt directory is unavailable",
    )?;
    require_path_absent(&prepared.receipt_path, "launch receipt already exists")
}

fn validate_selected_invocation(route_path: &Path, token: &LaunchToken) -> io::Result<()> {
    let validated = validate_issuance_route_invocation(
        Some(route_path.as_os_str().to_owned()),
        env::var_os(ISSUANCE_ROUTE_BENCHMARK_ID_ENV),
        &env::args_os().skip(1).collect::<Vec<_>>(),
    )?
    .ok_or_else(|| protocol_error("selected issuance invocation is incomplete"))?;
    if validated.destination != route_path {
        return Err(protocol_error("selected issuance invocation is invalid"));
    }
    let routes = qualification_routes(&issuance_benchmark_cases());
    let selected_benchmark_id = routes
        .get(validated.selected_route_index)
        .map(|route| route.benchmark_id.as_str())
        .ok_or_else(|| protocol_error("selected issuance invocation is invalid"))?;
    let scheduled_benchmark_id = scheduled_benchmark_id(
        token.global_round_ordinal,
        token.cell_ordinal,
        token.expansion_position,
    )
    .ok_or_else(|| protocol_error("launch token coordinate is invalid"))?;
    if selected_benchmark_id != scheduled_benchmark_id {
        return Err(protocol_error(
            "selected issuance invocation does not match the launch schedule",
        ));
    }
    Ok(())
}

fn scheduled_benchmark_id(
    global_round_ordinal: u32,
    cell_ordinal: u32,
    expansion_position: u32,
) -> Option<String> {
    let order = *SUPERBLOCK_ORDERS.get(usize::try_from(global_round_ordinal).ok()?)?;
    let expansion = usize::try_from(expansion_position).ok()?;
    let requested = match order {
        SuperblockOrder::AbbaFirst => *ABBA_EXPANSION.get(expansion)?,
        SuperblockOrder::BaabFirst => *BAAB_EXPANSION.get(expansion)?,
    };
    let cell = usize::try_from(cell_ordinal).ok()?;
    let paired_cells = qualification_paired_cells(&issuance_benchmark_cases());
    let id_field = match requested {
        IssuanceBenchmarkRoute::SerialOracle => "serial_id",
        IssuanceBenchmarkRoute::AdaptiveCandidate => "adaptive_id",
    };
    paired_cells
        .get(cell)?
        .get(id_field)?
        .as_str()
        .map(str::to_owned)
}

fn validate_token(token: &LaunchToken) -> io::Result<()> {
    if token.schema != TOKEN_SCHEMA
        || !valid_uuid_v4(&token.campaign_id)
        || token.global_round_ordinal >= MAX_GLOBAL_ROUNDS
        || token.cell_ordinal >= MAX_CELLS
        || token.expansion_position >= MAX_EXPANSION_POSITIONS
        || token.timing_process_id != timing_process_id(token)
        || !valid_uppercase_hex_256(&token.nonce_uppercase_hex_256)
        || !valid_uppercase_hex_256(&token.process_identity_pseudonym)
        || token.nonce_uppercase_hex_256 == token.process_identity_pseudonym
    {
        return Err(protocol_error("launch token identity is invalid"));
    }
    Ok(())
}

fn validate_release(
    prepared: &PreparedLaunchBarrier,
    release: &LaunchReleaseFrame,
) -> io::Result<()> {
    let token = &prepared.token;
    if release.schema != RELEASE_SCHEMA
        || release.campaign_id != token.campaign_id
        || release.global_round_ordinal != token.global_round_ordinal
        || release.cell_ordinal != token.cell_ordinal
        || release.expansion_position != token.expansion_position
        || release.timing_process_id != token.timing_process_id
        || release.process_identity_pseudonym != token.process_identity_pseudonym
        || release.launch_token_fingerprint != prepared.token_fingerprint
        || release.ready_frame_fingerprint != prepared.ready_fingerprint
        || !valid_artifact_fingerprint(
            &release.process_start_record_fingerprint,
            1,
            MAX_LAUNCH_FRAME_BYTES as u64,
        )
        || !valid_utc_rfc3339_nanoseconds(&release.prepared_at_utc_rfc3339_nanoseconds)
    {
        return Err(protocol_error(
            "launch release frame does not match the ready child",
        ));
    }
    Ok(())
}

fn timing_process_id(token: &LaunchToken) -> String {
    format!(
        "r{:02}-c{:02}-e{}",
        token.global_round_ordinal, token.cell_ordinal, token.expansion_position
    )
}

fn coordinate_stem(token: &LaunchToken) -> String {
    format!(
        "r{:02}_c{:02}_e{}",
        token.global_round_ordinal, token.cell_ordinal, token.expansion_position
    )
}

fn fixed_binary_name() -> &'static str {
    if cfg!(windows) {
        "fixed-benchmark.exe"
    } else {
        "fixed-benchmark"
    }
}

fn valid_uuid_v4(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && bytes[14] == b'4'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23)
                || byte.is_ascii_digit()
                || matches!(byte, b'a'..=b'f')
        })
}

fn valid_uppercase_hex_256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
}

fn valid_artifact_fingerprint(
    fingerprint: &ArtifactFingerprint,
    minimum_bytes: u64,
    maximum_bytes: u64,
) -> bool {
    fingerprint.sha256.len() == 64
        && fingerprint
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
        && (minimum_bytes..=maximum_bytes).contains(&fingerprint.byte_length)
}

fn valid_utc_rfc3339_nanoseconds(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 30
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[29] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19 | 29) && !byte.is_ascii_digit()
        })
    {
        return false;
    }

    let Some(year) = ascii_decimal(&bytes[0..4]) else {
        return false;
    };
    let Some(month) = ascii_decimal(&bytes[5..7]) else {
        return false;
    };
    let Some(day) = ascii_decimal(&bytes[8..10]) else {
        return false;
    };
    let Some(hour) = ascii_decimal(&bytes[11..13]) else {
        return false;
    };
    let Some(minute) = ascii_decimal(&bytes[14..16]) else {
        return false;
    };
    let Some(second) = ascii_decimal(&bytes[17..19]) else {
        return false;
    };
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return false,
    };
    year >= 1 && (1..=month_days).contains(&day) && hour <= 23 && minute <= 59 && second <= 59
}

fn ascii_decimal(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |value, byte| {
        value
            .checked_mul(10)?
            .checked_add(u32::from(byte.checked_sub(b'0')?))
    })
}

fn is_leap_year(year: u32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn required_utf8_path_env(name: &str) -> io::Result<PathBuf> {
    let value =
        env::var_os(name).ok_or_else(|| protocol_error("launch environment is incomplete"))?;
    path_from_utf8_os_string(value, "launch environment path is not UTF-8")
}

fn path_from_utf8_os_string(value: OsString, message: &'static str) -> io::Result<PathBuf> {
    value
        .into_string()
        .map(PathBuf::from)
        .map_err(|_| protocol_error(message))
}

fn require_exact_absolute_path(
    actual: &Path,
    expected: &Path,
    message: &'static str,
) -> io::Result<()> {
    if !actual.is_absolute() || actual != expected {
        return Err(protocol_error(message));
    }
    Ok(())
}

fn require_same_canonical_path(
    actual: &Path,
    expected: &Path,
    message: &'static str,
) -> io::Result<()> {
    let actual = fs::canonicalize(actual).map_err(|_| protocol_error(message))?;
    let expected = fs::canonicalize(expected).map_err(|_| protocol_error(message))?;
    if actual != expected {
        return Err(protocol_error(message));
    }
    Ok(())
}

fn require_directory(path: &Path, message: &'static str) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| protocol_error(message))?;
    if metadata.file_type().is_symlink()
        || metadata_is_reparse_point(&metadata)
        || !metadata.is_dir()
    {
        return Err(protocol_error(message));
    }
    Ok(())
}

fn require_empty_directory(path: &Path, message: &'static str) -> io::Result<()> {
    let mut entries = fs::read_dir(path).map_err(|_| protocol_error(message))?;
    match entries.next() {
        None => Ok(()),
        Some(Ok(_)) | Some(Err(_)) => Err(protocol_error(message)),
    }
}

fn require_path_absent(path: &Path, message: &'static str) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(protocol_error(message)),
    }
}

fn read_bounded_regular_file(
    path: &Path,
    maximum_bytes: usize,
    message: &'static str,
) -> io::Result<Vec<u8>> {
    let maximum_bytes = u64::try_from(maximum_bytes).map_err(|_| protocol_error(message))?;
    let mut file = BoundRegularFile::open(path, maximum_bytes, message)?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(file.initial.byte_length)
            .unwrap_or(64 * 1024)
            .min(64 * 1024),
    );
    (&mut file.file)
        .take(
            maximum_bytes
                .checked_add(1)
                .ok_or_else(|| protocol_error(message))?,
        )
        .read_to_end(&mut bytes)
        .map_err(|_| protocol_error(message))?;
    let byte_length = u64::try_from(bytes.len()).map_err(|_| protocol_error(message))?;
    if byte_length > maximum_bytes || byte_length != file.initial.byte_length {
        return Err(protocol_error(message));
    }
    file.verify_unchanged_and_bound()?;
    Ok(bytes)
}

fn fingerprint_regular_file(path: &Path, message: &'static str) -> io::Result<ArtifactFingerprint> {
    fingerprint_regular_file_bounded(path, MAX_FIXED_BINARY_BYTES, message)
}

fn fingerprint_regular_file_bounded(
    path: &Path,
    maximum_bytes: u64,
    message: &'static str,
) -> io::Result<ArtifactFingerprint> {
    let mut file = BoundRegularFile::open(path, maximum_bytes, message)?;
    if file.initial.byte_length == 0 {
        return Err(protocol_error(message));
    }
    let mut hasher = Sha256::new();
    let mut byte_length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    {
        let mut reader = (&mut file.file).take(
            maximum_bytes
                .checked_add(1)
                .ok_or_else(|| protocol_error(message))?,
        );
        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|_| protocol_error(message))?;
            if count == 0 {
                break;
            }
            byte_length = byte_length
                .checked_add(u64::try_from(count).map_err(|_| protocol_error(message))?)
                .ok_or_else(|| protocol_error(message))?;
            hasher.update(&buffer[..count]);
        }
    }
    if byte_length > maximum_bytes || byte_length != file.initial.byte_length {
        return Err(protocol_error(message));
    }
    file.verify_unchanged_and_bound()?;
    Ok(ArtifactFingerprint {
        sha256: uppercase_hex(&hasher.finalize()),
        byte_length,
    })
}

#[derive(Debug, Eq, PartialEq)]
struct RegularFileSnapshot {
    identity: PlatformFileIdentity,
    byte_length: u64,
    link_count: u64,
    attributes: u64,
    created: u64,
    modified: u64,
    modified_subsecond: i64,
    changed: u64,
    changed_subsecond: i64,
}

#[cfg(unix)]
#[derive(Debug, Eq, PartialEq)]
struct PlatformFileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(windows)]
#[derive(Debug, Eq, PartialEq)]
struct PlatformFileIdentity {
    volume_serial_number: u64,
    file_index: u64,
}

#[cfg(not(any(unix, windows)))]
#[derive(Debug, Eq, PartialEq)]
struct PlatformFileIdentity;

struct BoundRegularFile {
    file: File,
    path: PathBuf,
    initial: RegularFileSnapshot,
    maximum_bytes: u64,
    message: &'static str,
}

impl BoundRegularFile {
    fn open(path: &Path, maximum_bytes: u64, message: &'static str) -> io::Result<Self> {
        let path_metadata = checked_path_file_metadata(path, maximum_bytes, message)?;
        let file = open_regular_file_no_follow(path).map_err(|_| protocol_error(message))?;
        let initial = regular_file_snapshot(&file, maximum_bytes, message)?;
        if !path_metadata_matches_handle(&path_metadata, &initial) {
            return Err(protocol_error(message));
        }
        let bound = Self {
            file,
            path: path.to_path_buf(),
            initial,
            maximum_bytes,
            message,
        };
        bound.verify_unchanged_and_bound()?;
        Ok(bound)
    }

    fn verify_unchanged_and_bound(&self) -> io::Result<()> {
        let current = regular_file_snapshot(&self.file, self.maximum_bytes, self.message)?;
        if current != self.initial {
            return Err(protocol_error(self.message));
        }

        let path_metadata =
            checked_path_file_metadata(&self.path, self.maximum_bytes, self.message)?;
        let path_file =
            open_regular_file_no_follow(&self.path).map_err(|_| protocol_error(self.message))?;
        let path_snapshot = regular_file_snapshot(&path_file, self.maximum_bytes, self.message)?;
        if path_snapshot != self.initial
            || !path_metadata_matches_handle(&path_metadata, &path_snapshot)
        {
            return Err(protocol_error(self.message));
        }
        Ok(())
    }
}

fn checked_path_file_metadata(
    path: &Path,
    maximum_bytes: u64,
    message: &'static str,
) -> io::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).map_err(|_| protocol_error(message))?;
    if metadata.file_type().is_symlink()
        || metadata_is_reparse_point(&metadata)
        || !metadata.is_file()
        || metadata.len() > maximum_bytes
        || !path_metadata_has_one_link(&metadata)
    {
        return Err(protocol_error(message));
    }
    Ok(metadata)
}

#[cfg(unix)]
fn open_regular_file_no_follow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(windows)]
fn open_regular_file_no_follow(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(any(unix, windows)))]
fn open_regular_file_no_follow(_path: &Path) -> io::Result<File> {
    Err(protocol_error(
        "launch barrier file binding is unsupported on this platform",
    ))
}

#[cfg(unix)]
fn regular_file_snapshot(
    file: &File,
    maximum_bytes: u64,
    message: &'static str,
) -> io::Result<RegularFileSnapshot> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata().map_err(|_| protocol_error(message))?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > maximum_bytes {
        return Err(protocol_error(message));
    }
    Ok(RegularFileSnapshot {
        identity: PlatformFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        byte_length: metadata.len(),
        link_count: metadata.nlink(),
        attributes: u64::from(metadata.mode()),
        created: 0,
        modified: u64::from_ne_bytes(metadata.mtime().to_ne_bytes()),
        modified_subsecond: metadata.mtime_nsec(),
        changed: u64::from_ne_bytes(metadata.ctime().to_ne_bytes()),
        changed_subsecond: metadata.ctime_nsec(),
    })
}

#[cfg(windows)]
fn regular_file_snapshot(
    file: &File,
    maximum_bytes: u64,
    message: &'static str,
) -> io::Result<RegularFileSnapshot> {
    const FILE_ATTRIBUTE_DIRECTORY: u64 = 0x0000_0010;
    const FILE_ATTRIBUTE_REPARSE_POINT: u64 = 0x0000_0400;

    let information = winapi_util::file::information(file).map_err(|_| protocol_error(message))?;
    let file_type = winapi_util::file::typ(file).map_err(|_| protocol_error(message))?;
    let attributes = information.file_attributes();
    if !file_type.is_disk()
        || attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || information.number_of_links() != 1
        || information.file_size() > maximum_bytes
    {
        return Err(protocol_error(message));
    }
    Ok(RegularFileSnapshot {
        identity: PlatformFileIdentity {
            volume_serial_number: information.volume_serial_number(),
            file_index: information.file_index(),
        },
        byte_length: information.file_size(),
        link_count: information.number_of_links(),
        attributes,
        created: information.creation_time().unwrap_or(0),
        modified: information.last_write_time().unwrap_or(0),
        modified_subsecond: 0,
        changed: 0,
        changed_subsecond: 0,
    })
}

#[cfg(not(any(unix, windows)))]
fn regular_file_snapshot(
    _file: &File,
    _maximum_bytes: u64,
    message: &'static str,
) -> io::Result<RegularFileSnapshot> {
    Err(protocol_error(message))
}

#[cfg(unix)]
fn path_metadata_matches_handle(metadata: &fs::Metadata, snapshot: &RegularFileSnapshot) -> bool {
    use std::os::unix::fs::MetadataExt;

    RegularFileSnapshot {
        identity: PlatformFileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        byte_length: metadata.len(),
        link_count: metadata.nlink(),
        attributes: u64::from(metadata.mode()),
        created: 0,
        modified: u64::from_ne_bytes(metadata.mtime().to_ne_bytes()),
        modified_subsecond: metadata.mtime_nsec(),
        changed: u64::from_ne_bytes(metadata.ctime().to_ne_bytes()),
        changed_subsecond: metadata.ctime_nsec(),
    } == *snapshot
}

#[cfg(windows)]
fn path_metadata_matches_handle(metadata: &fs::Metadata, snapshot: &RegularFileSnapshot) -> bool {
    use std::os::windows::fs::MetadataExt;

    u64::from(metadata.file_attributes()) == snapshot.attributes
        && metadata.file_size() == snapshot.byte_length
        && metadata.creation_time() == snapshot.created
        && metadata.last_write_time() == snapshot.modified
}

#[cfg(not(any(unix, windows)))]
fn path_metadata_matches_handle(_metadata: &fs::Metadata, _snapshot: &RegularFileSnapshot) -> bool {
    false
}

fn fingerprint_bytes(bytes: &[u8]) -> io::Result<ArtifactFingerprint> {
    Ok(ArtifactFingerprint {
        sha256: uppercase_hex(&Sha256::digest(bytes)),
        byte_length: u64::try_from(bytes.len())
            .map_err(|_| protocol_error("artifact fingerprint length overflow"))?,
    })
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn path_metadata_has_one_link(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    metadata.nlink() == 1
}

#[cfg(not(unix))]
fn path_metadata_has_one_link(_metadata: &fs::Metadata) -> bool {
    true
}

fn uppercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn parse_canonical_pretty_json<T>(bytes: &[u8], message: &'static str) -> io::Result<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value = serde_json::from_slice(bytes).map_err(|_| protocol_error(message))?;
    if canonical_pretty_json(&value, message)? != bytes {
        return Err(protocol_error(message));
    }
    Ok(value)
}

fn parse_canonical_compact_json<T>(bytes: &[u8], message: &'static str) -> io::Result<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value = serde_json::from_slice(bytes).map_err(|_| protocol_error(message))?;
    if canonical_compact_json(&value, message)? != bytes {
        return Err(protocol_error(message));
    }
    Ok(value)
}

fn canonical_pretty_json<T: Serialize>(value: &T, message: &'static str) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|_| protocol_error(message))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn canonical_compact_json<T: Serialize>(value: &T, message: &'static str) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| protocol_error(message))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn create_new_durable_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| protocol_error("launch receipt parent path is invalid"))?;
    require_directory(parent, "launch receipt directory is unavailable")?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| protocol_error("launch receipt create-new failed"))?;
    file.write_all(bytes)
        .map_err(|_| protocol_error("launch receipt write failed"))?;
    file.flush()
        .map_err(|_| protocol_error("launch receipt flush failed"))?;
    file.sync_all()
        .map_err(|_| protocol_error("launch receipt durable sync failed"))?;
    drop(file);
    sync_parent_directory(parent)
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
        .map_err(|_| protocol_error("launch receipt parent sync failed"))?;
    directory
        .sync_all()
        .map_err(|_| protocol_error("launch receipt parent sync failed"))
}

#[cfg(windows)]
fn sync_parent_directory(_parent: &Path) -> io::Result<()> {
    // On Windows `File::sync_all` maps to `FlushFileBuffers` for the newly
    // created file and attempts to flush its contents and metadata. Do not
    // infer a separate Unix-style parent-directory-entry flush guarantee.
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_parent_directory(_parent: &Path) -> io::Result<()> {
    Err(protocol_error(
        "launch receipt parent sync is unsupported on this platform",
    ))
}

fn protocol_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static NEXT_SCRATCH: AtomicUsize = AtomicUsize::new(0);

    struct ScratchDirectory(PathBuf);

    impl ScratchDirectory {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let ordinal = NEXT_SCRATCH.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "sd-jwt-launch-barrier-unit-{label}-{}-{nonce}-{ordinal}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for ScratchDirectory {
        fn drop(&mut self) {
            assert!(self.0.starts_with(env::temp_dir()));
            if self.0.exists() {
                fs::remove_dir_all(&self.0).unwrap();
            }
        }
    }

    fn token() -> LaunchToken {
        LaunchToken {
            schema: TOKEN_SCHEMA.to_owned(),
            campaign_id: "018f4f9a-3f5b-4ae8-8a37-11c9fc12d001".to_owned(),
            global_round_ordinal: 3,
            cell_ordinal: 7,
            expansion_position: 2,
            timing_process_id: "r03-c07-e2".to_owned(),
            nonce_uppercase_hex_256: "A".repeat(64),
            process_identity_pseudonym: "B".repeat(64),
        }
    }

    fn fingerprint(byte_length: u64, digit: char) -> ArtifactFingerprint {
        ArtifactFingerprint {
            sha256: digit.to_string().repeat(64),
            byte_length,
        }
    }

    fn prepared() -> PreparedLaunchBarrier {
        let token = token();
        PreparedLaunchBarrier {
            token,
            token_fingerprint: fingerprint(200, '1'),
            fixed_binary_fingerprint: fingerprint(10_000, '2'),
            ready_bytes: b"ready\n".to_vec(),
            ready_fingerprint: fingerprint(300, '3'),
            campaign_root: PathBuf::from("unused"),
            criterion_home: PathBuf::from("unused"),
            route_path: PathBuf::from("unused"),
            temp_path: PathBuf::from("unused"),
            receipt_path: PathBuf::from("unused"),
        }
    }

    fn release(prepared: &PreparedLaunchBarrier) -> LaunchReleaseFrame {
        LaunchReleaseFrame {
            schema: RELEASE_SCHEMA.to_owned(),
            campaign_id: prepared.token.campaign_id.clone(),
            global_round_ordinal: prepared.token.global_round_ordinal,
            cell_ordinal: prepared.token.cell_ordinal,
            expansion_position: prepared.token.expansion_position,
            timing_process_id: prepared.token.timing_process_id.clone(),
            process_identity_pseudonym: prepared.token.process_identity_pseudonym.clone(),
            launch_token_fingerprint: prepared.token_fingerprint.clone(),
            ready_frame_fingerprint: prepared.ready_fingerprint.clone(),
            process_start_record_fingerprint: fingerprint(512, 'A'),
            prepared_at_utc_rfc3339_nanoseconds: "2026-08-29T12:34:56.123456789Z".to_owned(),
            prepared_at_monotonic_nanoseconds: 123,
        }
    }

    #[test]
    fn frozen_schedule_binds_all_10_560_coordinates_to_the_registered_route() {
        assert_eq!(
            SUPERBLOCK_ORDERS,
            [
                SuperblockOrder::AbbaFirst,
                SuperblockOrder::BaabFirst,
                SuperblockOrder::BaabFirst,
                SuperblockOrder::AbbaFirst,
                SuperblockOrder::BaabFirst,
                SuperblockOrder::AbbaFirst,
                SuperblockOrder::AbbaFirst,
                SuperblockOrder::BaabFirst,
                SuperblockOrder::AbbaFirst,
                SuperblockOrder::BaabFirst,
                SuperblockOrder::BaabFirst,
                SuperblockOrder::AbbaFirst,
                SuperblockOrder::AbbaFirst,
                SuperblockOrder::BaabFirst,
                SuperblockOrder::BaabFirst,
                SuperblockOrder::AbbaFirst,
                SuperblockOrder::BaabFirst,
                SuperblockOrder::AbbaFirst,
                SuperblockOrder::BaabFirst,
                SuperblockOrder::AbbaFirst,
            ]
        );
        assert_eq!(
            ABBA_EXPANSION,
            [
                IssuanceBenchmarkRoute::SerialOracle,
                IssuanceBenchmarkRoute::AdaptiveCandidate,
                IssuanceBenchmarkRoute::AdaptiveCandidate,
                IssuanceBenchmarkRoute::SerialOracle,
                IssuanceBenchmarkRoute::AdaptiveCandidate,
                IssuanceBenchmarkRoute::SerialOracle,
                IssuanceBenchmarkRoute::SerialOracle,
                IssuanceBenchmarkRoute::AdaptiveCandidate,
            ]
        );
        assert_eq!(
            BAAB_EXPANSION,
            [
                IssuanceBenchmarkRoute::AdaptiveCandidate,
                IssuanceBenchmarkRoute::SerialOracle,
                IssuanceBenchmarkRoute::SerialOracle,
                IssuanceBenchmarkRoute::AdaptiveCandidate,
                IssuanceBenchmarkRoute::SerialOracle,
                IssuanceBenchmarkRoute::AdaptiveCandidate,
                IssuanceBenchmarkRoute::AdaptiveCandidate,
                IssuanceBenchmarkRoute::SerialOracle,
            ]
        );

        let cases = issuance_benchmark_cases();
        let routes = qualification_routes(&cases);
        let paired_cells = qualification_paired_cells(&cases);
        let mut coordinate_count = 0_usize;
        let mut serial_count = 0_usize;
        let mut adaptive_count = 0_usize;
        for global_round_ordinal in 0..MAX_GLOBAL_ROUNDS {
            let expansion_routes = match SUPERBLOCK_ORDERS[global_round_ordinal as usize] {
                SuperblockOrder::AbbaFirst => ABBA_EXPANSION,
                SuperblockOrder::BaabFirst => BAAB_EXPANSION,
            };
            for cell_ordinal in 0..MAX_CELLS {
                let cell = cell_ordinal as usize;
                let paired_cell = &paired_cells[cell];
                for expansion_position in 0..MAX_EXPANSION_POSITIONS {
                    let requested = expansion_routes[expansion_position as usize];
                    let id_field = match requested {
                        IssuanceBenchmarkRoute::SerialOracle => "serial_id",
                        IssuanceBenchmarkRoute::AdaptiveCandidate => "adaptive_id",
                    };
                    let expected = paired_cell[id_field].as_str().unwrap();
                    assert_eq!(
                        scheduled_benchmark_id(
                            global_round_ordinal,
                            cell_ordinal,
                            expansion_position,
                        )
                        .as_deref(),
                        Some(expected)
                    );
                    assert!(routes.iter().any(|route| {
                        route.benchmark_id == expected
                            && route.stage.label() == paired_cell["stage"].as_str().unwrap()
                            && route.requested == requested
                    }));
                    match requested {
                        IssuanceBenchmarkRoute::SerialOracle => serial_count += 1,
                        IssuanceBenchmarkRoute::AdaptiveCandidate => adaptive_count += 1,
                    }
                    coordinate_count += 1;
                }
            }
        }

        assert_eq!(coordinate_count, 10_560);
        assert_eq!(serial_count, 5_280);
        assert_eq!(adaptive_count, 5_280);
        assert_eq!(
            scheduled_benchmark_id(3, 7, 2).as_deref(),
            Some("sd_jwt_issuance/v2__s_fi__r_ac__p_s__d_0__n_0128")
        );
        assert_eq!(
            scheduled_benchmark_id(0, 0, 0).as_deref(),
            Some("sd_jwt_issuance/v2__s_ea__r_so__p_s__d_0__n_0001")
        );
        assert_eq!(
            scheduled_benchmark_id(1, 0, 0).as_deref(),
            Some("sd_jwt_issuance/v2__s_ea__r_ac__p_s__d_0__n_0001")
        );
        assert_eq!(
            scheduled_benchmark_id(19, 65, 7).as_deref(),
            Some("sd_jwt_issuance/v2__s_fi__r_ac__f_tl_imbalanced_n0008")
        );
        assert!(scheduled_benchmark_id(MAX_GLOBAL_ROUNDS, 0, 0).is_none());
        assert!(scheduled_benchmark_id(0, MAX_CELLS, 0).is_none());
        assert!(scheduled_benchmark_id(0, 0, MAX_EXPANSION_POSITIONS).is_none());
    }

    #[test]
    fn token_identity_grammar_is_exact() {
        assert!(validate_token(&token()).is_ok());
        let mutations: [fn(&mut LaunchToken); 10] = [
            |value| value.schema.push('x'),
            |value| value.campaign_id.make_ascii_uppercase(),
            |value| value.campaign_id.replace_range(14..15, "5"),
            |value| value.global_round_ordinal = MAX_GLOBAL_ROUNDS,
            |value| value.cell_ordinal = MAX_CELLS,
            |value| value.expansion_position = MAX_EXPANSION_POSITIONS,
            |value| value.timing_process_id = "r3-c07-e2".to_owned(),
            |value| value.nonce_uppercase_hex_256.make_ascii_lowercase(),
            |value| value.process_identity_pseudonym.push('A'),
            |value| value.process_identity_pseudonym = value.nonce_uppercase_hex_256.clone(),
        ];
        for mutation in mutations {
            let mut candidate = token();
            mutation(&mut candidate);
            assert!(validate_token(&candidate).is_err());
        }
    }

    #[test]
    fn canonical_token_rejects_lexical_and_structural_drift() {
        let canonical = canonical_pretty_json(&token(), "test").unwrap();
        assert_eq!(
            parse_canonical_pretty_json::<LaunchToken>(&canonical, "test").unwrap(),
            token()
        );

        let text = String::from_utf8(canonical).unwrap();
        let invalid = [
            text.trim_end().as_bytes().to_vec(),
            text.replace("  \"schema\"", " \"schema\"").into_bytes(),
            text.replace("\n", "\r\n").into_bytes(),
            text.replacen(
                "  \"schema\"",
                "  \"unknown\": true,\n  \"schema\"",
                1,
            )
            .into_bytes(),
            text.replacen(
                "  \"campaign_id\"",
                "  \"schema\": \"marty.performance/sd-jwt-issuance-launch-token/v1\",\n  \"campaign_id\"",
                1,
            )
            .into_bytes(),
            vec![0xff, b'\n'],
        ];
        for candidate in invalid {
            assert!(parse_canonical_pretty_json::<LaunchToken>(&candidate, "test").is_err());
        }
    }

    #[test]
    fn release_requires_exact_identity_and_causal_fingerprints() {
        let prepared = prepared();
        assert!(validate_release(&prepared, &release(&prepared)).is_ok());
        let mutations: [fn(&mut LaunchReleaseFrame); 12] = [
            |value| value.schema.push('x'),
            |value| value.campaign_id.push('x'),
            |value| value.global_round_ordinal += 1,
            |value| value.cell_ordinal += 1,
            |value| value.expansion_position += 1,
            |value| value.timing_process_id.push('x'),
            |value| value.process_identity_pseudonym.replace_range(0..1, "C"),
            |value| {
                value
                    .launch_token_fingerprint
                    .sha256
                    .replace_range(0..1, "f")
            },
            |value| value.ready_frame_fingerprint.byte_length += 1,
            |value| {
                value
                    .process_start_record_fingerprint
                    .sha256
                    .make_ascii_lowercase()
            },
            |value| value.process_start_record_fingerprint.byte_length = 0,
            |value| {
                value
                    .prepared_at_utc_rfc3339_nanoseconds
                    .replace_range(10..11, "t")
            },
        ];
        for mutation in mutations {
            let mut candidate = release(&prepared);
            mutation(&mut candidate);
            assert!(validate_release(&prepared, &candidate).is_err());
        }
    }

    #[test]
    fn release_canonical_frame_rejects_partial_extra_second_and_non_utf8_data() {
        let prepared = prepared();
        let canonical = canonical_compact_json(&release(&prepared), "test").unwrap();
        assert!(canonical.len() <= MAX_LAUNCH_FRAME_BYTES);
        assert!(parse_canonical_compact_json::<LaunchReleaseFrame>(&canonical, "test").is_ok());

        let mut extra = canonical.clone();
        extra.push(b' ');
        let mut second = canonical.clone();
        second.extend_from_slice(&canonical);
        let mut noncanonical = canonical.clone();
        noncanonical.insert(1, b' ');
        for candidate in [
            Vec::new(),
            canonical[..canonical.len() - 1].to_vec(),
            extra,
            second,
            noncanonical,
            vec![0xff, b'\n'],
        ] {
            assert!(
                parse_canonical_compact_json::<LaunchReleaseFrame>(&candidate, "test").is_err()
            );
        }
    }

    #[test]
    fn frozen_fingerprints_are_exact_uppercase_hex() {
        let abc = fingerprint_bytes(b"abc").unwrap();
        assert_eq!(
            abc.sha256,
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        );
        assert!(valid_artifact_fingerprint(&abc, 3, 3));
        let mut case_drift = abc;
        case_drift.sha256.make_ascii_lowercase();
        assert!(!valid_artifact_fingerprint(&case_drift, 3, 3));
    }

    #[test]
    fn ready_frame_bytes_match_the_frozen_v3_field_order() {
        let prepared = prepared();
        let ready = LaunchReadyFrame {
            schema: READY_SCHEMA.to_owned(),
            campaign_id: prepared.token.campaign_id,
            global_round_ordinal: prepared.token.global_round_ordinal,
            cell_ordinal: prepared.token.cell_ordinal,
            expansion_position: prepared.token.expansion_position,
            timing_process_id: prepared.token.timing_process_id,
            process_identity_pseudonym: prepared.token.process_identity_pseudonym,
            launch_token_fingerprint: prepared.token_fingerprint,
            fixed_binary_fingerprint: prepared.fixed_binary_fingerprint,
        };
        let expected = concat!(
            "{\"schema\":\"marty.performance/sd-jwt-issuance-launch-ready/v1\",",
            "\"campaign_id\":\"018f4f9a-3f5b-4ae8-8a37-11c9fc12d001\",",
            "\"global_round_ordinal\":3,\"cell_ordinal\":7,\"expansion_position\":2,",
            "\"timing_process_id\":\"r03-c07-e2\",",
            "\"process_identity_pseudonym\":",
            "\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\",",
            "\"launch_token_fingerprint\":{",
            "\"sha256\":\"1111111111111111111111111111111111111111111111111111111111111111\",",
            "\"byte_length\":200},\"fixed_binary_fingerprint\":{",
            "\"sha256\":\"2222222222222222222222222222222222222222222222222222222222222222\",",
            "\"byte_length\":10000}}\n"
        );
        assert_eq!(
            canonical_compact_json(&ready, "test").unwrap(),
            expected.as_bytes()
        );
    }

    #[test]
    fn opened_file_binding_rejects_added_hard_link_and_size_change() {
        let scratch = ScratchDirectory::new("binding");
        let path = scratch.0.join("input");
        fs::write(&path, b"bound bytes").unwrap();

        let hard_link = scratch.0.join("hard-link");
        let bound = BoundRegularFile::open(&path, 64, "test").unwrap();
        fs::hard_link(&path, &hard_link).unwrap();
        assert!(bound.verify_unchanged_and_bound().is_err());
        drop(bound);
        fs::remove_file(&hard_link).unwrap();

        let bound = BoundRegularFile::open(&path, 64, "test").unwrap();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"!")
            .unwrap();
        assert!(bound.verify_unchanged_and_bound().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn opened_file_binding_rejects_final_symlink() {
        use std::os::unix::fs::symlink;

        let scratch = ScratchDirectory::new("symlink");
        let target = scratch.0.join("target");
        let link = scratch.0.join("link");
        fs::write(&target, b"bound bytes").unwrap();
        symlink(&target, &link).unwrap();
        assert!(BoundRegularFile::open(&link, 64, "test").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn opened_file_binding_rejects_final_reparse_link_when_host_allows_creation() {
        use std::os::windows::fs::symlink_file;

        let scratch = ScratchDirectory::new("reparse-link");
        let target = scratch.0.join("target");
        let link = scratch.0.join("link");
        fs::write(&target, b"bound bytes").unwrap();
        if let Err(error) = symlink_file(&target, &link) {
            if matches!(error.raw_os_error(), Some(5 | 1_314)) {
                return;
            }
            panic!("unexpected reparse-link creation failure: {error}");
        }
        assert!(BoundRegularFile::open(&link, 64, "test").is_err());
    }

    #[test]
    fn receipt_creation_is_create_new_and_returns_only_after_sync() {
        let scratch = ScratchDirectory::new("receipt");
        let path = scratch.0.join("receipt.json");
        create_new_durable_file(&path, b"receipt\n").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"receipt\n");
        assert!(create_new_durable_file(&path, b"replacement\n").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"receipt\n");
    }

    #[test]
    fn fixed_binary_fingerprint_rejects_over_bound_input_without_large_allocation() {
        let scratch = ScratchDirectory::new("binary-cap");
        let path = scratch.0.join("fixed-benchmark");
        fs::write(&path, b"two bytes").unwrap();
        assert!(fingerprint_regular_file_bounded(&path, 1, "test").is_err());
    }

    #[test]
    fn utc_nanosecond_grammar_checks_calendar_and_leap_seconds() {
        for valid in [
            "2024-02-29T00:00:00.000000000Z",
            "2000-02-29T23:59:59.999999999Z",
            "2026-08-29T12:34:56.123456789Z",
        ] {
            assert!(valid_utc_rfc3339_nanoseconds(valid));
        }
        for invalid in [
            "0000-01-01T00:00:00.000000000Z",
            "1900-02-29T00:00:00.000000000Z",
            "2026-02-29T00:00:00.000000000Z",
            "2026-08-29T24:00:00.000000000Z",
            "2026-08-29T12:60:00.000000000Z",
            "2026-08-29T12:34:60.000000000Z",
            "2026-08-29t12:34:56.123456789Z",
            "2026-08-29T12:34:56.12345678Z",
            "2026-08-29T12:34:56.123456789+00:00",
        ] {
            assert!(!valid_utc_rfc3339_nanoseconds(invalid));
        }
    }

    #[test]
    fn frame_and_auxiliary_caps_match_frozen_v3() {
        assert_eq!(MAX_LAUNCH_FRAME_BYTES, 65_536);
        assert_eq!(MAX_BARRIER_ARTIFACT_BYTES, 16_777_216);
        assert_eq!(MAX_FIXED_BINARY_BYTES, 2_147_483_648);
    }
}
