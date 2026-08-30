// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

//! Controller-side smoke tests for the installed fixed benchmark binary.
//!
//! These tests are ignored by default because they require the separately
//! built custom Criterion binary named by
//! `SD_JWT_LAUNCH_BARRIER_FIXED_BINARY_UNDER_TEST`.

#![cfg(not(target_arch = "wasm32"))]

use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const FIXED_BINARY_ENV: &str = "SD_JWT_LAUNCH_BARRIER_FIXED_BINARY_UNDER_TEST";
const SELECTED_BENCHMARK_ID: &str = "sd_jwt_issuance/v2__s_fi__r_ac__p_s__d_0__n_0128";
const WRONG_SCHEDULED_BENCHMARK_ID: &str = "sd_jwt_issuance/v2__s_ea__r_so__p_s__d_0__n_0001";
const TOKEN_SCHEMA: &str = "marty.performance/sd-jwt-issuance-launch-token/v1";
const READY_SCHEMA: &str = "marty.performance/sd-jwt-issuance-launch-ready/v1";
const RELEASE_SCHEMA: &str = "marty.performance/sd-jwt-issuance-launch-release/v1";
const RECEIPT_SCHEMA: &str = "marty.performance/sd-jwt-issuance-launch-receipt/v1";
const MAX_LAUNCH_FRAME_BYTES: usize = 64 * 1024;
const MAX_BARRIER_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
const PROCESS_PSEUDONYM: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

static NEXT_ROOT: AtomicUsize = AtomicUsize::new(0);

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

struct CampaignFixture {
    root: PathBuf,
    fixed_binary: PathBuf,
    criterion_home: PathBuf,
    token_path: PathBuf,
    route_path: PathBuf,
    receipt_path: PathBuf,
    temp_path: PathBuf,
    token: LaunchToken,
    token_fingerprint: ArtifactFingerprint,
    fixed_binary_fingerprint: ArtifactFingerprint,
    windows_runtime: Option<OsString>,
}

impl CampaignFixture {
    fn new(label: &str) -> Self {
        let source_binary = env::var_os(FIXED_BINARY_ENV)
            .map(PathBuf::from)
            .expect("set SD_JWT_LAUNCH_BARRIER_FIXED_BINARY_UNDER_TEST to the built bench binary");
        assert!(source_binary.is_absolute());
        assert!(source_binary.is_file());

        let root = unique_root(label);
        fs::create_dir(&root).unwrap();
        for role in [
            "barriers",
            "barrier-receipts",
            "bin",
            "criterion",
            "routes",
            "tmp",
        ] {
            fs::create_dir(root.join(role)).unwrap();
        }

        let coordinate_stem = "r03_c07_e2";
        let criterion_home = root.join("criterion").join(coordinate_stem);
        let temp_path = root.join("tmp").join(coordinate_stem);
        fs::create_dir(&criterion_home).unwrap();
        fs::create_dir(&temp_path).unwrap();

        let fixed_binary = root.join("bin").join(if cfg!(windows) {
            "fixed-benchmark.exe"
        } else {
            "fixed-benchmark"
        });
        fs::copy(&source_binary, &fixed_binary).unwrap();
        make_executable(&fixed_binary);

        let token = LaunchToken {
            schema: TOKEN_SCHEMA.to_owned(),
            campaign_id: "018f4f9a-3f5b-4ae8-8a37-11c9fc12d001".to_owned(),
            global_round_ordinal: 3,
            cell_ordinal: 7,
            expansion_position: 2,
            timing_process_id: "r03-c07-e2".to_owned(),
            nonce_uppercase_hex_256: "A".repeat(64),
            process_identity_pseudonym: PROCESS_PSEUDONYM.to_owned(),
        };
        let token_bytes = canonical_pretty(&token);
        let token_path = root
            .join("barriers")
            .join(format!("{coordinate_stem}.token"));
        write_create_new_durable(&token_path, &token_bytes);

        let route_path = root
            .join("routes")
            .join(format!("{coordinate_stem}.ndjson"));
        let receipt_path = root
            .join("barrier-receipts")
            .join(format!("{coordinate_stem}.json"));
        let windows_runtime = if cfg!(windows) {
            Some(env::var_os("SystemRoot").expect("Windows must expose SystemRoot"))
        } else {
            None
        };

        Self {
            root,
            fixed_binary_fingerprint: fingerprint_file(&fixed_binary),
            token_fingerprint: fingerprint_bytes(&token_bytes),
            fixed_binary,
            criterion_home,
            token_path,
            route_path,
            receipt_path,
            temp_path,
            token,
            windows_runtime,
        }
    }

    fn command(&self) -> Command {
        self.command_for(&self.fixed_binary)
    }

    fn command_for(&self, executable: &Path) -> Command {
        self.command_for_selection(executable, SELECTED_BENCHMARK_ID)
    }

    fn command_for_selection(&self, executable: &Path, selected_benchmark_id: &str) -> Command {
        let mut command = Command::new(executable);
        command
            .current_dir(&self.root)
            .env_clear()
            .env("CRITERION_HOME", &self.criterion_home)
            .env("MARTY_PERF_START_BARRIER", &self.token_path)
            .env("NO_COLOR", "1")
            .env("RUST_BACKTRACE", "0")
            .env("SD_JWT_ISSUANCE_ROUTE_BENCHMARK_ID", selected_benchmark_id)
            .env("SD_JWT_ISSUANCE_ROUTE_NDJSON", &self.route_path)
            .env("TEMP", &self.temp_path)
            .env("TMP", &self.temp_path)
            .args(qualification_arguments(selected_benchmark_id))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(runtime) = &self.windows_runtime {
            command.env("SystemRoot", runtime).env("WINDIR", runtime);
        }
        command
    }

    fn replace_token_bytes(&self, bytes: &[u8]) {
        fs::remove_file(&self.token_path).unwrap();
        write_create_new_durable(&self.token_path, bytes);
    }

    fn expected_ready(&self) -> LaunchReadyFrame {
        LaunchReadyFrame {
            schema: READY_SCHEMA.to_owned(),
            campaign_id: self.token.campaign_id.clone(),
            global_round_ordinal: self.token.global_round_ordinal,
            cell_ordinal: self.token.cell_ordinal,
            expansion_position: self.token.expansion_position,
            timing_process_id: self.token.timing_process_id.clone(),
            process_identity_pseudonym: self.token.process_identity_pseudonym.clone(),
            launch_token_fingerprint: self.token_fingerprint.clone(),
            fixed_binary_fingerprint: self.fixed_binary_fingerprint.clone(),
        }
    }

    fn release(&self, ready_bytes: &[u8]) -> LaunchReleaseFrame {
        LaunchReleaseFrame {
            schema: RELEASE_SCHEMA.to_owned(),
            campaign_id: self.token.campaign_id.clone(),
            global_round_ordinal: self.token.global_round_ordinal,
            cell_ordinal: self.token.cell_ordinal,
            expansion_position: self.token.expansion_position,
            timing_process_id: self.token.timing_process_id.clone(),
            process_identity_pseudonym: self.token.process_identity_pseudonym.clone(),
            launch_token_fingerprint: self.token_fingerprint.clone(),
            ready_frame_fingerprint: fingerprint_bytes(ready_bytes),
            process_start_record_fingerprint: ArtifactFingerprint {
                sha256: "C".repeat(64),
                byte_length: 512,
            },
            prepared_at_utc_rfc3339_nanoseconds: "2026-08-29T12:34:56.123456789Z".to_owned(),
            prepared_at_monotonic_nanoseconds: 123_456_789,
        }
    }

    fn expected_receipt(
        &self,
        ready_bytes: &[u8],
        release_bytes: &[u8],
        release: &LaunchReleaseFrame,
    ) -> LaunchReceipt {
        LaunchReceipt {
            schema: RECEIPT_SCHEMA.to_owned(),
            campaign_id: self.token.campaign_id.clone(),
            global_round_ordinal: self.token.global_round_ordinal,
            cell_ordinal: self.token.cell_ordinal,
            expansion_position: self.token.expansion_position,
            timing_process_id: self.token.timing_process_id.clone(),
            process_identity_pseudonym: self.token.process_identity_pseudonym.clone(),
            launch_token_fingerprint: self.token_fingerprint.clone(),
            ready_frame_fingerprint: fingerprint_bytes(ready_bytes),
            release_frame_fingerprint: fingerprint_bytes(release_bytes),
            process_start_record_fingerprint: release.process_start_record_fingerprint.clone(),
            fixed_binary_fingerprint: self.fixed_binary_fingerprint.clone(),
        }
    }
}

impl Drop for CampaignFixture {
    fn drop(&mut self) {
        let temporary_root = env::temp_dir();
        assert!(self.root.starts_with(&temporary_root));
        if self.root.exists() {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }
}

struct OutputReader {
    ready: Receiver<io::Result<Vec<u8>>>,
    first_after_ready: Receiver<io::Result<Option<u8>>>,
    thread: JoinHandle<io::Result<Vec<u8>>>,
}

impl OutputReader {
    fn start(child: &mut Child) -> Self {
        let stdout = child.stdout.take().expect("child stdout must be piped");
        let (ready_tx, ready) = mpsc::channel();
        let (first_tx, first_after_ready) = mpsc::channel();
        let thread = thread::spawn(move || {
            let mut stdout = BufReader::new(stdout);
            let mut ready_bytes = Vec::new();
            let ready_result = stdout
                .read_until(b'\n', &mut ready_bytes)
                .map(|_| ready_bytes);
            ready_tx
                .send(ready_result)
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "ready receiver closed"))?;

            let mut first = [0_u8; 1];
            let count = stdout.read(&mut first)?;
            first_tx
                .send(Ok((count == 1).then_some(first[0])))
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tail receiver closed"))?;
            let mut tail = if count == 1 {
                vec![first[0]]
            } else {
                Vec::new()
            };
            stdout.read_to_end(&mut tail)?;
            Ok(tail)
        });
        Self {
            ready,
            first_after_ready,
            thread,
        }
    }

    fn receive_ready(&self) -> Vec<u8> {
        self.ready
            .recv_timeout(Duration::from_secs(10))
            .expect("fixed binary must emit ready within ten seconds")
            .expect("fixed binary ready read must succeed")
    }

    fn finish(self) -> Vec<u8> {
        self.thread
            .join()
            .expect("stdout reader must not panic")
            .expect("stdout reader must succeed")
    }
}

#[test]
#[ignore = "requires SD_JWT_LAUNCH_BARRIER_FIXED_BINARY_UNDER_TEST"]
fn fixed_binary_blocks_before_release_and_syncs_exact_receipt() {
    let fixture = CampaignFixture::new("positive");
    let mut child = fixture.command().spawn().unwrap();
    let output = OutputReader::start(&mut child);
    let ready_bytes = output.receive_ready();
    assert_eq!(ready_bytes, canonical_compact(&fixture.expected_ready()));
    assert!(!fixture.receipt_path.exists());
    assert!(!fixture.route_path.exists());
    assert!(fs::read_dir(&fixture.criterion_home)
        .unwrap()
        .next()
        .is_none());
    assert!(child.try_wait().unwrap().is_none());
    assert!(matches!(
        output
            .first_after_ready
            .recv_timeout(Duration::from_millis(250)),
        Err(RecvTimeoutError::Timeout)
    ));
    assert!(child.try_wait().unwrap().is_none());

    let release = fixture.release(&ready_bytes);
    let release_bytes = canonical_compact(&release);
    let mut stdin = child.stdin.take().expect("child stdin must be piped");
    stdin.write_all(&release_bytes).unwrap();
    stdin.flush().unwrap();
    drop(stdin);

    // `benchmark_issuance` create-new opens the route sink as its first
    // operation after `benches()` constructs Criterion. Observing that path
    // therefore proves the barrier returned after its receipt sync; it does
    // not depend on completion of a timed benchmark. Keep the wait bounded so
    // a startup regression cannot deadlock this smoke.
    wait_for_path(
        &fixture.route_path,
        Duration::from_secs(10),
        "post-barrier route sink",
    );
    let receipt_bytes = fs::read(&fixture.receipt_path).unwrap();
    let expected_receipt = fixture.expected_receipt(&ready_bytes, &release_bytes, &release);
    assert_eq!(receipt_bytes, canonical_pretty(&expected_receipt));
    assert_eq!(
        parse_canonical_pretty::<LaunchReceipt>(&receipt_bytes),
        expected_receipt
    );

    stop_child(&mut child);
    let _ = output.finish();
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    assert!(!String::from_utf8_lossy(&stderr).contains(PROCESS_PSEUDONYM));
}

#[test]
#[ignore = "requires SD_JWT_LAUNCH_BARRIER_FIXED_BINARY_UNDER_TEST"]
fn fixed_binary_rejects_receipt_parent_replacement_after_ready() {
    let fixture = CampaignFixture::new("parent-swap-after-ready");
    let mut child = fixture.command().spawn().unwrap();
    let output = OutputReader::start(&mut child);
    let ready_bytes = output.receive_ready();
    assert_eq!(ready_bytes, canonical_compact(&fixture.expected_ready()));

    let original_parent = fixture.root.join("barrier-receipts");
    let retained_parent = fixture.root.join("barrier-receipts-original");
    fs::rename(&original_parent, &retained_parent).unwrap();
    replace_receipt_parent_with_link_or_nondirectory(&fixture, &original_parent);

    let release = fixture.release(&ready_bytes);
    let mut stdin = child.stdin.take().expect("child stdin must be piped");
    stdin.write_all(&canonical_compact(&release)).unwrap();
    stdin.flush().unwrap();
    drop(stdin);

    let status = wait_for_exit(&mut child, Duration::from_secs(10));
    assert_eq!(status.code(), Some(2));
    assert!(output.finish().is_empty());
    let mut stderr = Vec::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    let stderr = String::from_utf8(stderr).unwrap();
    assert!(stderr.starts_with("SD-JWT issuance launch barrier rejected:"));
    for forbidden in [
        fixture.root.to_string_lossy().as_ref(),
        fixture.token.campaign_id.as_str(),
        PROCESS_PSEUDONYM,
        SELECTED_BENCHMARK_ID,
    ] {
        assert!(!stderr.contains(forbidden));
    }
    assert!(!retained_parent.join("r03_c07_e2.json").exists());
    assert!(!fixture.route_path.exists());
    assert!(fs::read_dir(&fixture.criterion_home)
        .unwrap()
        .next()
        .is_none());
}

#[cfg(windows)]
#[test]
#[ignore = "requires SD_JWT_LAUNCH_BARRIER_FIXED_BINARY_UNDER_TEST"]
fn fixed_binary_rejects_final_binary_reparse_when_host_allows_creation() {
    use std::os::windows::fs::symlink_file;

    let fixture = CampaignFixture::new("fixed-binary-reparse");
    let real_binary = fixture.root.join("bin").join("real-benchmark.exe");
    fs::rename(&fixture.fixed_binary, &real_binary).unwrap();
    if let Err(error) = symlink_file(&real_binary, &fixture.fixed_binary) {
        if matches!(error.raw_os_error(), Some(5 | 1_314)) {
            return;
        }
        panic!("unexpected reparse-link creation failure: {error}");
    }

    let output = fixture.command().output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("SD-JWT issuance launch barrier rejected:"));
    for forbidden in [
        fixture.root.to_string_lossy().as_ref(),
        fixture.token.campaign_id.as_str(),
        PROCESS_PSEUDONYM,
        SELECTED_BENCHMARK_ID,
    ] {
        assert!(!stderr.contains(forbidden));
    }
    assert!(!fixture.receipt_path.exists());
    assert!(!fixture.route_path.exists());
    assert!(fs::read_dir(&fixture.criterion_home)
        .unwrap()
        .next()
        .is_none());
}

#[test]
#[ignore = "requires SD_JWT_LAUNCH_BARRIER_FIXED_BINARY_UNDER_TEST"]
fn fixed_binary_rejects_release_negative_corpus_before_criterion() {
    let fixture = CampaignFixture::new("negative-release");
    let baseline = MutableEvidenceSnapshot::capture(&fixture);
    let expected_ready = canonical_compact(&fixture.expected_ready());
    let release = fixture.release(&expected_ready);
    let canonical = canonical_compact(&release);

    let mut mismatch = release.clone();
    mismatch.process_identity_pseudonym = "C".repeat(64);
    let mut case_drift = release.clone();
    case_drift.schema.make_ascii_uppercase();
    let mut fingerprint_case_drift = release.clone();
    fingerprint_case_drift
        .process_start_record_fingerprint
        .sha256
        .make_ascii_lowercase();
    let mut noncanonical = canonical.clone();
    noncanonical.insert(1, b' ');
    let mut extra = canonical.clone();
    extra.push(b' ');
    let mut second = canonical.clone();
    second.extend_from_slice(&canonical);
    let mut unknown = canonical.clone();
    unknown.splice(1..1, b"\"unknown\":true,".iter().copied());
    let corpus = [
        ("early-eof", Vec::new()),
        ("partial", canonical[..canonical.len() - 1].to_vec()),
        ("extra", extra),
        ("second", second),
        ("noncanonical", noncanonical),
        ("unknown", unknown),
        ("non-utf8", vec![0xff, b'\n']),
        ("mismatch", canonical_compact(&mismatch)),
        ("case-drift", canonical_compact(&case_drift)),
        (
            "fingerprint-case-drift",
            canonical_compact(&fingerprint_case_drift),
        ),
        ("oversize", vec![b'x'; MAX_LAUNCH_FRAME_BYTES + 1]),
    ];

    for (label, release_bytes) in corpus {
        assert!(
            !fixture.receipt_path.exists(),
            "precondition failed for {label}"
        );
        let mut child = fixture.command().spawn().unwrap();
        let output = OutputReader::start(&mut child);
        let ready_bytes = output.receive_ready();
        assert_eq!(ready_bytes, expected_ready, "ready mismatch for {label}");

        let mut stdin = child.stdin.take().expect("child stdin must be piped");
        stdin.write_all(&release_bytes).unwrap();
        stdin.flush().unwrap();
        drop(stdin);

        let status = wait_for_exit(&mut child, Duration::from_secs(10));
        assert_eq!(status.code(), Some(2), "unexpected exit for {label}");
        let tail = output.finish();
        assert!(tail.is_empty(), "Criterion stdout observed for {label}");
        let mut stderr = Vec::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_end(&mut stderr)
            .unwrap();
        let stderr = String::from_utf8(stderr).unwrap();
        assert!(stderr.starts_with("SD-JWT issuance launch barrier rejected:"));
        for forbidden in [
            fixture.root.to_string_lossy().as_ref(),
            fixture.token.campaign_id.as_str(),
            PROCESS_PSEUDONYM,
            SELECTED_BENCHMARK_ID,
        ] {
            assert!(!stderr.contains(forbidden), "diagnostic leak for {label}");
        }
        assert_eq!(
            MutableEvidenceSnapshot::capture(&fixture),
            baseline,
            "mutable evidence changed for {label}"
        );
    }
}

#[derive(Clone, Copy, Debug)]
enum PreReadyMutation {
    MalformedToken,
    NoncanonicalToken,
    NonUtf8Token,
    OversizeToken,
    TokenIdentityMismatch,
    TokenCoordinateMismatch,
    TokenPathMismatch,
    ExtraEnvironment,
    MissingEnvironment,
    LiteralEnvironmentDrift,
    IncompleteSelectedInvocation,
    MismatchedSelectedInvocation,
    WrongScheduledRoute,
    MismatchedArguments,
    MismatchedRoutePath,
    NonemptyCriterionHome,
    ExistingRoute,
    ReusedReceipt,
    WrongFixedBinaryPath,
    TokenHardLink,
    FixedBinaryHardLink,
    #[cfg(unix)]
    TokenSymlink,
    #[cfg(unix)]
    FixedBinarySymlink,
    #[cfg(unix)]
    CriterionParentSymlink,
    #[cfg(unix)]
    TempParentSymlink,
}

impl PreReadyMutation {
    const PORTABLE: [Self; 21] = [
        Self::MalformedToken,
        Self::NoncanonicalToken,
        Self::NonUtf8Token,
        Self::OversizeToken,
        Self::TokenIdentityMismatch,
        Self::TokenCoordinateMismatch,
        Self::TokenPathMismatch,
        Self::ExtraEnvironment,
        Self::MissingEnvironment,
        Self::LiteralEnvironmentDrift,
        Self::IncompleteSelectedInvocation,
        Self::MismatchedSelectedInvocation,
        Self::WrongScheduledRoute,
        Self::MismatchedArguments,
        Self::MismatchedRoutePath,
        Self::NonemptyCriterionHome,
        Self::ExistingRoute,
        Self::ReusedReceipt,
        Self::WrongFixedBinaryPath,
        Self::TokenHardLink,
        Self::FixedBinaryHardLink,
    ];

    fn all() -> Vec<Self> {
        #[cfg(not(unix))]
        {
            Self::PORTABLE.to_vec()
        }
        #[cfg(unix)]
        {
            let mut mutations = Self::PORTABLE.to_vec();
            mutations.extend([
                Self::TokenSymlink,
                Self::FixedBinarySymlink,
                Self::CriterionParentSymlink,
                Self::TempParentSymlink,
            ]);
            mutations
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::MalformedToken => "malformed-token",
            Self::NoncanonicalToken => "noncanonical-token",
            Self::NonUtf8Token => "non-utf8-token",
            Self::OversizeToken => "oversize-token",
            Self::TokenIdentityMismatch => "token-identity",
            Self::TokenCoordinateMismatch => "token-coordinate",
            Self::TokenPathMismatch => "token-path",
            Self::ExtraEnvironment => "extra-environment",
            Self::MissingEnvironment => "missing-environment",
            Self::LiteralEnvironmentDrift => "literal-environment",
            Self::IncompleteSelectedInvocation => "incomplete-selected-invocation",
            Self::MismatchedSelectedInvocation => "mismatched-selected-invocation",
            Self::WrongScheduledRoute => "wrong-scheduled-route",
            Self::MismatchedArguments => "mismatched-arguments",
            Self::MismatchedRoutePath => "mismatched-route-path",
            Self::NonemptyCriterionHome => "nonempty-criterion-home",
            Self::ExistingRoute => "existing-route",
            Self::ReusedReceipt => "reused-receipt",
            Self::WrongFixedBinaryPath => "wrong-fixed-binary-path",
            Self::TokenHardLink => "token-hard-link",
            Self::FixedBinaryHardLink => "fixed-binary-hard-link",
            #[cfg(unix)]
            Self::TokenSymlink => "token-symlink",
            #[cfg(unix)]
            Self::FixedBinarySymlink => "fixed-binary-symlink",
            #[cfg(unix)]
            Self::CriterionParentSymlink => "criterion-parent-symlink",
            #[cfg(unix)]
            Self::TempParentSymlink => "temp-parent-symlink",
        }
    }

    fn prepare(self, fixture: &CampaignFixture) -> PathBuf {
        match self {
            Self::MalformedToken => fixture.replace_token_bytes(b"{\n"),
            Self::NoncanonicalToken => {
                fixture.replace_token_bytes(&canonical_compact(&fixture.token))
            }
            Self::NonUtf8Token => fixture.replace_token_bytes(&[0xff, b'\n']),
            Self::OversizeToken => {
                fixture.replace_token_bytes(&vec![b'x'; MAX_BARRIER_ARTIFACT_BYTES + 1])
            }
            Self::TokenIdentityMismatch => {
                let mut token = fixture.token.clone();
                token.campaign_id.make_ascii_uppercase();
                fixture.replace_token_bytes(&canonical_pretty(&token));
            }
            Self::TokenCoordinateMismatch => {
                let mut token = fixture.token.clone();
                token.global_round_ordinal += 1;
                fixture.replace_token_bytes(&canonical_pretty(&token));
            }
            Self::TokenPathMismatch => {
                let wrong = fixture.root.join("barriers").join("r03_c07_e3.token");
                write_create_new_durable(&wrong, &canonical_pretty(&fixture.token));
            }
            Self::NonemptyCriterionHome => {
                write_create_new_durable(&fixture.criterion_home.join("unexpected"), b"x")
            }
            Self::ExistingRoute => write_create_new_durable(&fixture.route_path, b"existing"),
            Self::ReusedReceipt => write_create_new_durable(&fixture.receipt_path, b"existing"),
            Self::WrongFixedBinaryPath => {
                let wrong = fixture.root.join("bin").join(if cfg!(windows) {
                    "other-benchmark.exe"
                } else {
                    "other-benchmark"
                });
                fs::copy(&fixture.fixed_binary, &wrong).unwrap();
                make_executable(&wrong);
                return wrong;
            }
            Self::TokenHardLink => {
                fs::hard_link(
                    &fixture.token_path,
                    fixture.root.join("barriers").join("token-hard-link"),
                )
                .unwrap();
            }
            Self::FixedBinaryHardLink => {
                fs::hard_link(
                    &fixture.fixed_binary,
                    fixture.root.join("bin").join("fixed-binary-hard-link"),
                )
                .unwrap();
            }
            #[cfg(unix)]
            Self::TokenSymlink => prepare_token_symlink(fixture),
            #[cfg(unix)]
            Self::FixedBinarySymlink => prepare_fixed_binary_symlink(fixture),
            #[cfg(unix)]
            Self::CriterionParentSymlink => prepare_parent_symlink(fixture, "criterion"),
            #[cfg(unix)]
            Self::TempParentSymlink => prepare_parent_symlink(fixture, "tmp"),
            Self::ExtraEnvironment
            | Self::MissingEnvironment
            | Self::LiteralEnvironmentDrift
            | Self::IncompleteSelectedInvocation
            | Self::MismatchedSelectedInvocation
            | Self::WrongScheduledRoute
            | Self::MismatchedArguments
            | Self::MismatchedRoutePath => {}
        }
        fixture.fixed_binary.clone()
    }

    fn mutate_command(self, fixture: &CampaignFixture, command: &mut Command) {
        match self {
            Self::TokenPathMismatch => {
                command.env(
                    "MARTY_PERF_START_BARRIER",
                    fixture.root.join("barriers").join("r03_c07_e3.token"),
                );
            }
            Self::ExtraEnvironment => {
                command.env("UNEXPECTED_ENVIRONMENT", "forbidden");
            }
            Self::MissingEnvironment => {
                command.env_remove("NO_COLOR");
            }
            Self::LiteralEnvironmentDrift => {
                command.env("NO_COLOR", "0");
            }
            Self::IncompleteSelectedInvocation => {
                command.env_remove("SD_JWT_ISSUANCE_ROUTE_BENCHMARK_ID");
            }
            Self::MismatchedSelectedInvocation => {
                command.env(
                    "SD_JWT_ISSUANCE_ROUTE_BENCHMARK_ID",
                    "sd_jwt_issuance/v2__s_ea__r_so__p_s__d_0__n_9999",
                );
            }
            Self::WrongScheduledRoute => {}
            Self::MismatchedArguments => {
                command.arg("--verbose");
            }
            Self::MismatchedRoutePath => {
                command.env(
                    "SD_JWT_ISSUANCE_ROUTE_NDJSON",
                    fixture.root.join("routes").join("wrong.ndjson"),
                );
            }
            Self::MalformedToken
            | Self::NoncanonicalToken
            | Self::NonUtf8Token
            | Self::OversizeToken
            | Self::TokenIdentityMismatch
            | Self::TokenCoordinateMismatch
            | Self::NonemptyCriterionHome
            | Self::ExistingRoute
            | Self::ReusedReceipt
            | Self::WrongFixedBinaryPath
            | Self::TokenHardLink
            | Self::FixedBinaryHardLink => {}
            #[cfg(unix)]
            Self::TokenSymlink
            | Self::FixedBinarySymlink
            | Self::CriterionParentSymlink
            | Self::TempParentSymlink => {}
        }
    }
}

#[cfg(unix)]
fn prepare_token_symlink(fixture: &CampaignFixture) {
    use std::os::unix::fs::symlink;

    let real_token = fixture.root.join("barriers").join("real.token");
    fs::rename(&fixture.token_path, &real_token).unwrap();
    symlink(&real_token, &fixture.token_path).unwrap();
}

#[cfg(unix)]
fn prepare_fixed_binary_symlink(fixture: &CampaignFixture) {
    use std::os::unix::fs::symlink;

    let real_binary = fixture.root.join("bin").join("real-benchmark");
    fs::rename(&fixture.fixed_binary, &real_binary).unwrap();
    symlink(&real_binary, &fixture.fixed_binary).unwrap();
}

#[cfg(unix)]
fn prepare_parent_symlink(fixture: &CampaignFixture, role: &str) {
    use std::os::unix::fs::symlink;

    let original = fixture.root.join(role);
    let real = fixture.root.join(format!("{role}-real"));
    fs::rename(&original, &real).unwrap();
    symlink(&real, &original).unwrap();
}

#[cfg(unix)]
fn replace_receipt_parent_with_link_or_nondirectory(
    fixture: &CampaignFixture,
    original_parent: &Path,
) {
    use std::os::unix::fs::symlink;

    let redirected = fixture.root.join("barrier-receipts-redirected");
    fs::create_dir(&redirected).unwrap();
    symlink(&redirected, original_parent).unwrap();
}

#[cfg(not(unix))]
fn replace_receipt_parent_with_link_or_nondirectory(
    _fixture: &CampaignFixture,
    original_parent: &Path,
) {
    write_create_new_durable(original_parent, b"not a directory")
}

#[derive(Debug, Eq, PartialEq)]
struct MutableEvidenceSnapshot {
    criterion: BTreeMap<String, Option<Vec<u8>>>,
    temporary: BTreeMap<String, Option<Vec<u8>>>,
    route: Option<Vec<u8>>,
    receipt: Option<Vec<u8>>,
}

impl MutableEvidenceSnapshot {
    fn capture(fixture: &CampaignFixture) -> Self {
        Self {
            criterion: tree_snapshot(&fixture.criterion_home),
            temporary: tree_snapshot(&fixture.temp_path),
            route: read_optional(&fixture.route_path),
            receipt: read_optional(&fixture.receipt_path),
        }
    }
}

#[test]
#[ignore = "requires SD_JWT_LAUNCH_BARRIER_FIXED_BINARY_UNDER_TEST"]
fn fixed_binary_rejects_pre_ready_negative_corpus_without_mutation() {
    for mutation in PreReadyMutation::all() {
        let label = mutation.label();
        let fixture = CampaignFixture::new(label);
        let executable = mutation.prepare(&fixture);
        let before = MutableEvidenceSnapshot::capture(&fixture);
        let selected_benchmark_id = if matches!(mutation, PreReadyMutation::WrongScheduledRoute) {
            WRONG_SCHEDULED_BENCHMARK_ID
        } else {
            SELECTED_BENCHMARK_ID
        };
        let mut command = fixture.command_for_selection(&executable, selected_benchmark_id);
        mutation.mutate_command(&fixture, &mut command);
        let output = command.output().unwrap();

        assert_eq!(output.status.code(), Some(2), "unexpected exit for {label}");
        assert!(output.stdout.is_empty(), "stdout observed for {label}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.starts_with("SD-JWT issuance launch barrier rejected:"));
        for forbidden in [
            fixture.root.to_string_lossy().as_ref(),
            fixture.token.campaign_id.as_str(),
            PROCESS_PSEUDONYM,
            SELECTED_BENCHMARK_ID,
            WRONG_SCHEDULED_BENCHMARK_ID,
            "n_9999",
        ] {
            assert!(!stderr.contains(forbidden), "diagnostic leak for {label}");
        }
        assert_eq!(
            MutableEvidenceSnapshot::capture(&fixture),
            before,
            "mutable evidence changed for {label}"
        );
    }
}

fn qualification_arguments(selected_benchmark_id: &str) -> [&str; 16] {
    [
        "--bench",
        "--exact",
        selected_benchmark_id,
        "--sample-size",
        "50",
        "--nresamples",
        "100000",
        "--warm-up-time",
        "15",
        "--measurement-time",
        "10",
        "--confidence-level",
        "0.95",
        "--save-baseline",
        "base",
        "--noplot",
    ]
}

fn unique_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let ordinal = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
    env::temp_dir().join(format!(
        "sd-jwt-launch-barrier-{label}-{}-{nonce}-{ordinal}",
        std::process::id()
    ))
}

fn write_create_new_durable(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.flush().unwrap();
    file.sync_all().unwrap();
}

fn canonical_pretty<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn canonical_compact<T: Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}

fn parse_canonical_pretty<T>(bytes: &[u8]) -> T
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value = serde_json::from_slice(bytes).unwrap();
    assert_eq!(canonical_pretty(&value), bytes);
    value
}

fn fingerprint_bytes(bytes: &[u8]) -> ArtifactFingerprint {
    ArtifactFingerprint {
        sha256: uppercase_hex(&Sha256::digest(bytes)),
        byte_length: u64::try_from(bytes.len()).unwrap(),
    }
}

fn fingerprint_file(path: &Path) -> ArtifactFingerprint {
    let mut file = File::open(path).unwrap();
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        length += u64::try_from(count).unwrap();
    }
    ArtifactFingerprint {
        sha256: uppercase_hex(&hasher.finalize()),
        byte_length: length,
    }
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

fn tree_snapshot(root: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    fn visit(root: &Path, current: &Path, snapshot: &mut BTreeMap<String, Option<Vec<u8>>>) {
        let mut entries = fs::read_dir(current)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let metadata = entry.metadata().unwrap();
            if metadata.is_dir() {
                snapshot.insert(relative, None);
                visit(root, &path, snapshot);
            } else {
                snapshot.insert(relative, Some(fs::read(path).unwrap()));
            }
        }
    }

    let mut snapshot = BTreeMap::new();
    visit(root, root, &mut snapshot);
    snapshot
}

fn read_optional(path: &Path) -> Option<Vec<u8>> {
    path.exists().then(|| fs::read(path).unwrap())
}

fn wait_for_path(path: &Path, timeout: Duration, role: &str) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        assert!(Instant::now() < deadline, "timed out waiting for {role}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("timed out waiting for fixed binary exit");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn stop_child(child: &mut Child) {
    if child.try_wait().unwrap().is_none() {
        child.kill().unwrap();
    }
    child.wait().unwrap();
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}

#[test]
fn fixed_binary_environment_name_is_not_forwarded_to_the_child() {
    assert_ne!(FIXED_BINARY_ENV, "MARTY_PERF_START_BARRIER");
    assert_ne!(OsStr::new(FIXED_BINARY_ENV), OsStr::new("CRITERION_HOME"));
}
