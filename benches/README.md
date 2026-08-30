# SD-JWT benchmarks

`sd_jwt_verification` measures the existing public `SDJWTVerifier::new` boundary.
Each measured invocation parses compact serialization, decodes and parses every
presented disclosure, hashes disclosures, verifies the issuer signature, detects
duplicates, and reconstructs disclosed claims.

The matrix covers 1, 8, 32, 128, and 512 disclosures across small strings,
medium nested objects, 64 KiB strings, and a mixed-size sequence. Criterion
reports one element per completed credential verification, so throughput is
credentials per second. Fixture generation, salt allocation, and issuer signing
occur before the timed iterations. Input cloning and public-key parsing also use
Criterion's untimed setup closure.

The 512-disclosure large case contains 32 MiB of raw disclosed claim data before
JSON and Base64url expansion, so its compact presentation and memory footprint
are larger. Keep enough free memory available and compare it only on machines
that can run both revisions without paging.

Hosted CI runs `cargo test --benches` as a compile and one-iteration smoke gate.
Do not apply wall-clock performance thresholds to shared CI runners.

## Production RNG acquisition microcase

`sd_jwt_production_rng` exercises the public production issuance path with 512
top-level disclosures and root decoys. Claim cloning and issuer-key parsing are
outside the timed closure; salt generation, decoy-count sampling, planning,
signing, and serialization are timed. This keeps production `ThreadRng` handle
acquisition in the measured path, unlike the deterministic qualification tape
below. Run it without `mock_salts`:

```sh
cargo bench --locked --no-default-features --bench sd_jwt_production_rng
```

This scalar case is directional local evidence, not a release threshold. The
frozen qualification matrix and its launch protocol remain unchanged.

## Issuance executor qualification fixture

`sd_jwt_issuance` is an opt-in harness for comparing the immutable serial
issuance oracle with the bounded adaptive candidate on one exact source tree.
It requires `--features issuance_bench`; that feature implies `parallel`, but
`parallel` does not imply `issuance_bench`. Ordinary builds therefore neither
compile the fixture surface nor change issuer routing. In particular,
`QUALIFIED_ISSUANCE_THRESHOLDS` remains `None` until separate benchmark evidence
supports a production policy.

The first 30 fixture cases contain the required 1, 8, 32, 128, and 512 top-level
disclosures for each of small, medium nested, 64 KiB large, and mixed nested
values. Ten additional cases enable decoys for small values (root decoys) and
mixed values (root and nested-object decoys). Decoy counts deterministically
cycle through 2, 3, and 4 per object. Every disclosure and decoy salt starts as
an independently domain-separated deterministic 16-byte input and is encoded
to exactly 22 Base64url characters, matching the production salt length without
using the process-global `mock_salts` queue.

Three focused structural cases complete the 33-case matrix. The
`al_nested_obj_n0007` AllLevels object tree has three dependency levels and
exact ready batches `(2,72)`, `(2,72)`, and `(3,314)`. The
`al_array_dag_n0008` AllLevels array graph has exact ready batches `(2,62)`,
`(2,62)`, `(2,274)`, and `(2,185)`. The `tl_imbalanced_n0008` TopLevel root
keeps two contiguous 4 KiB string jobs before six empty-string jobs, producing
one `(8,8480)` batch with ordered job weights
`[4132,4132,36,36,36,36,36,36]`. The order is deliberate so contiguous static
partitioning exposes rather than hides load imbalance.

Qualification of the four-worker imbalanced layout requires at least four host
threads, no worker-budget fallback, and exact contiguous chunk loads
`[8264,72,72,72]` in both stages. Lower-parallelism runs remain correctness
evidence but cannot qualify that layout.

Each fixture registers four IDs:

- `executor_assembly` constructs the complete immutable `IssuancePlan` in
  Criterion's untimed `iter_batched` setup and times only execution,
  deterministic restoration, and assembly.
- `full_issuance` clones claims and the random tape, then constructs issuer
  state around a pre-parsed signing key in untimed setup. It times planning,
  assembly, ES256 signing, and compact serialization.
- `serial_oracle` calls the exact serial implementation.
- `adaptive_candidate` uses the real per-ready-batch adaptive selector, shared
  non-blocking worker-budget lease, four-worker cap, bounded native executor,
  and serial fallbacks. Its benchmark-only eligibility floors are two ready
  jobs and one estimated byte; these are mechanical exercise controls, not a
  proposed production threshold.

Before timing, both stages require exact serial/candidate output equality.
The harness constructs one compact JSON route record for each of the 132 exact
Criterion IDs, including requested and effective routes, ready-batch counts,
budget fallbacks, maximum native workers, host parallelism, and the worker cap.
A one-job ready batch, a single-thread host, worker-budget contention, ARM64,
and WASM can therefore be recorded as serial fallback rather than mislabeled
as native work. Ready-batch count fields are JSON `null` for the serial oracle
and for whole-plan target fallback because neither path invokes the adaptive
batch executor; numeric zero is reserved for an observed adaptive execution
with no batches of that kind. IDs use compact, stable codes so Criterion 0.5
neither truncates directory names nor creates order-dependent collision
suffixes. The JSON record carries the expanded labels. The ID schema is:

```text
sd_jwt_issuance/v2__s_<ea|fi>__r_<so|ac>__p_<s|mn|l64|mx>__d_<0|1>__n_<zero-padded-count>
sd_jwt_issuance/v2__s_<ea|fi>__r_<so|ac>__f_<al_nested_obj_n0007|al_array_dag_n0008|tl_imbalanced_n0008>
```

Here `ea`/`fi` select executor assembly/full issuance, `so`/`ac` select the
serial oracle/adaptive candidate, and `s`/`mn`/`l64`/`mx` select the four
payload classes. The `f` form names one of the three exact structural fixtures.

Compile and one-iteration smoke gate:

```sh
cargo test --locked --no-default-features --features issuance_bench --bench sd_jwt_issuance --verbose
```

Criterion run:

```sh
cargo bench --locked --no-default-features --features issuance_bench --bench sd_jwt_issuance -- --verbose
```

Frozen selected-ID qualification uses the exact logical Criterion 0.5.1
arguments below. The qualification controller invokes the already-built fixed
benchmark binary directly and supplies the complete vector as shown. A Cargo
wrapper is not the frozen path because its custom-harness arguments can differ.

```text
--bench --exact {full_benchmark_id} --sample-size 50 --nresamples 100000 --warm-up-time 15 --measurement-time 10 --confidence-level 0.95 --save-baseline base --noplot
```

Set `SD_JWT_ISSUANCE_ROUTE_BENCHMARK_ID` to exactly the substituted full ID and
`SD_JWT_ISSUANCE_ROUTE_NDJSON` to an absolute create-new destination. Both must
be present or both absent. In selected mode the harness still constructs and
validates the complete ordered 132-record preflight matrix, including each
ID/requested-route pairing, before it projects the matching record. The output
is exactly one canonical compact UTF-8 record plus one LF, with no BOM, CR, or
extra bytes; it is capped at 1 MiB, flushed, and durably synced. Unknown,
partial, case-drifted, mismatched, duplicate, missing, extra, reordered, or
route-swapped evidence is rejected. Diagnostics do not reproduce the selected
ID. With both variables absent, the ordinary benchmark creates no evidence
file.

### Frozen launch barrier

The qualification controller additionally sets `MARTY_PERF_START_BARRIER` to
the absolute coordinate token path and invokes the installed binary from the
campaign root with only the frozen environment allowlist. The custom binary
entrypoint runs before `criterion_group!` constructs Criterion. It validates
the canonical pretty token (under the v3 16 MiB auxiliary-artifact cap), UUID
v4 campaign identity, coordinate and process pseudonym, the fixed executable
at `bin/fixed-benchmark[.exe]`, the empty unique Criterion home, route and temp
paths, the exact argument vector, and the selected full ID against the route
scheduled for that coordinate by the frozen 20-round ABBA/BAAB expansion.

The child then writes and flushes one canonical compact ready frame plus LF as
the first stdout bytes. Its next protocol operation is a blocking stdin read
through EOF under the 64 KiB frame cap. It rejects early EOF, partial, extra,
second, noncanonical, oversized, non-UTF-8, or identity/fingerprint-mismatched
release bytes. A valid release produces the exact canonical pretty receipt at
`barrier-receipts/rNN_cNN_eN.json` using create-new, flush, and durable sync
before Criterion construction. Diagnostics never reproduce the campaign ID,
process pseudonym, selected benchmark ID, or host path. When the barrier
variable is absent, the ordinary benchmark path remains unchanged.

The trusted controller has exclusive ownership of the campaign root and must
keep every parent directory unchanged from spawn through child exit. The child
uses no-follow opens and handle identity/link/size checks for the token and
fixed binary, rejects static symlink/reparse/hard-link inputs, and revalidates
mutable paths after release. It does not claim race-resistant sandboxing
against another local actor swapping an ordinary parent between path
operations. Such a mutation violates the trusted-controller,
quiescent-ancestry assumption and invalidates the campaign operationally;
detecting it is outside the child-side guarantee. On Unix the receipt file and
its no-follow parent directory are both synced. On Windows `File::sync_all`
attempts to flush the receipt contents and metadata; there is no separate
Unix-style parent-directory-entry flush claim.
Fixed-binary hashing is streamed and fails closed above the frozen
2,147,483,648-byte build-input cap.

The real-child smoke is deliberately ignored unless a separately built custom
benchmark binary is supplied. For example on PowerShell, after resolving the
compiler-artifact executable from the JSON build output:

```powershell
cargo build --locked --profile bench --no-default-features --features issuance_bench --bench sd_jwt_issuance --message-format=json
$env:SD_JWT_LAUNCH_BARRIER_FIXED_BINARY_UNDER_TEST = "C:\absolute\target\release\deps\sd_jwt_issuance-<hash>.exe"
cargo test --locked --no-default-features --features issuance_bench --test issuance_launch_barrier_fixed_binary -- --ignored
Remove-Item Env:\SD_JWT_LAUNCH_BARRIER_FIXED_BINARY_UNDER_TEST
```

The smoke proves the installed binary blocks before release, emits no bytes
before the ready frame or after it while blocked, syncs the exact receipt after
release, and rejects both the pre-ready and release-frame negative corpora
without constructing Criterion or mutating route/receipt/home/temp evidence.

Keep this feature on the same exact revision for both requested routes; unlike
the verification benchmark, it does not require two separately compiled
feature modes. Preserve each selected `sd_jwt_issuance_route_v2` record with
its matching Criterion estimates so a later runner can reject an
expected-native case that actually fell back to serial execution. The complete
preflight matrix is valid only with all 132 unique expected IDs in exact
registration order; missing, duplicate, extra, reordered, or route-swapped
records prevent projection. Benchmark IDs are `v2` because the fixture matrix
changed. The route-evidence schema remains
`sd_jwt_issuance_route_v2`, while the work estimator and contiguous static
partition labels intentionally remain their independently versioned `v1`
contracts.

Each adaptive `ready_batches` entry records the exact selector inputs and gate
evaluation state, selected and leased workers, stable selection reason, and,
for native execution, the contiguous static chunk counts and estimated loads.
The estimator and partition rule have independent version labels. Aggregate
batch counters are derived from these records. `ready_batches` is JSON `null`
for the serial oracle and whole-target fallback; `[]` means the adaptive
executor was genuinely observed and received no ready batches. This evidence
is emitted only by the untimed preflight and contains aggregate sizes and
counts, never claim names, claim values, salts, job identities, or structural
locations.

## Reproducible comparison

Use the same idle machine for both revisions. Keep Cargo target directories
separate so equal package names and versions cannot reuse artifacts from the
other worktree, and share only Criterion's measurement directory. If the base
revision predates this benchmark, create a detached worktree and cherry-pick
only the benchmark-harness commit; that commit must contain no production
source changes.

PowerShell:

```powershell
$featureWorktree = git rev-parse --show-toplevel
$baselineWorktree = "C:\tmp\sd-jwt-verification-baseline"
$baseCommit = "88587cb23a814e5c6271bb781235f8f29027020b"
$harnessCommit = "99756cbc682f5b9874834255f20a32618ff0e57e"
$oldCriterionHome = [Environment]::GetEnvironmentVariable("CRITERION_HOME", "Process")
$oldCargoTargetDir = [Environment]::GetEnvironmentVariable("CARGO_TARGET_DIR", "Process")
$baselineAdded = $false

if ($baseCommit -notmatch '^[0-9a-fA-F]{40}$') {
    throw "Set baseCommit to the exact full baseline commit SHA"
}
if ($harnessCommit -notmatch '^[0-9a-fA-F]{40}$') {
    throw "Set harnessCommit to the exact full benchmark-harness commit SHA"
}
git cat-file -e "${baseCommit}^{commit}"
if ($LASTEXITCODE -ne 0) { throw "Baseline commit is unavailable" }
git cat-file -e "${harnessCommit}^{commit}"
if ($LASTEXITCODE -ne 0) { throw "Benchmark-harness commit is unavailable" }
if (Test-Path -LiteralPath $baselineWorktree) {
    throw "Baseline worktree path already exists: $baselineWorktree"
}

try {
    $baselineAdded = $true
    git worktree add --detach $baselineWorktree $baseCommit
    if ($LASTEXITCODE -ne 0) { throw "Could not create baseline worktree" }
    git -C $baselineWorktree cherry-pick $harnessCommit
    if ($LASTEXITCODE -ne 0) { throw "Could not apply benchmark harness" }

    $env:CRITERION_HOME = "C:\tmp\sd-jwt-verification-criterion"
    $env:CARGO_TARGET_DIR = "C:\tmp\sd-jwt-verification-baseline-target"
    cargo bench --manifest-path "$baselineWorktree\Cargo.toml" --bench sd_jwt_verification -- --save-baseline main --verbose
    if ($LASTEXITCODE -ne 0) { throw "Baseline benchmark failed" }

    $env:CARGO_TARGET_DIR = "C:\tmp\sd-jwt-verification-feature-target"
    cargo bench --manifest-path "$featureWorktree\Cargo.toml" --bench sd_jwt_verification -- --baseline main --verbose
    if ($LASTEXITCODE -ne 0) { throw "Feature benchmark failed" }
} finally {
    if ($baselineAdded) {
        git worktree remove --force $baselineWorktree
    }
    [Environment]::SetEnvironmentVariable("CRITERION_HOME", $oldCriterionHome, "Process")
    [Environment]::SetEnvironmentVariable("CARGO_TARGET_DIR", $oldCargoTargetDir, "Process")
}
```

POSIX shell:

```sh
set -eu

feature_worktree=$(git rev-parse --show-toplevel)
baseline_worktree=/tmp/sd-jwt-verification-baseline
base_commit='88587cb23a814e5c6271bb781235f8f29027020b'
harness_commit='99756cbc682f5b9874834255f20a32618ff0e57e'
old_criterion_home_is_set=${CRITERION_HOME+x}
old_criterion_home=${CRITERION_HOME-}
old_cargo_target_dir_is_set=${CARGO_TARGET_DIR+x}
old_cargo_target_dir=${CARGO_TARGET_DIR-}
baseline_added=0

cleanup() {
  status=$?
  if [ "$baseline_added" -eq 1 ]; then
    git worktree remove --force "$baseline_worktree" || true
    baseline_added=0
  fi
  if [ "$old_criterion_home_is_set" = x ]; then
    export CRITERION_HOME=$old_criterion_home
  else
    unset CRITERION_HOME
  fi
  if [ "$old_cargo_target_dir_is_set" = x ]; then
    export CARGO_TARGET_DIR=$old_cargo_target_dir
  else
    unset CARGO_TARGET_DIR
  fi
  return "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

if [ "${#base_commit}" -ne 40 ]; then
  echo "Set base_commit to the exact full baseline commit SHA" >&2
  exit 1
fi
case "$base_commit" in
  *[!0-9a-fA-F]*)
    echo "Set base_commit to the exact full baseline commit SHA" >&2
    exit 1
    ;;
esac
if [ "${#harness_commit}" -ne 40 ]; then
  echo "Set harness_commit to the exact full benchmark-harness commit SHA" >&2
  exit 1
fi
case "$harness_commit" in
  *[!0-9a-fA-F]*)
    echo "Set harness_commit to the exact full benchmark-harness commit SHA" >&2
    exit 1
    ;;
esac
git cat-file -e "$base_commit^{commit}"
git cat-file -e "$harness_commit^{commit}"
if [ -e "$baseline_worktree" ]; then
  echo "Baseline worktree path already exists: $baseline_worktree" >&2
  exit 1
fi

baseline_added=1
git worktree add --detach "$baseline_worktree" "$base_commit"
git -C "$baseline_worktree" cherry-pick "$harness_commit"

export CRITERION_HOME=/tmp/sd-jwt-verification-criterion
CARGO_TARGET_DIR=/tmp/sd-jwt-verification-baseline-target \
  cargo bench --manifest-path "$baseline_worktree/Cargo.toml" \
  --bench sd_jwt_verification -- --save-baseline main --verbose

CARGO_TARGET_DIR=/tmp/sd-jwt-verification-feature-target \
  cargo bench --manifest-path "$feature_worktree/Cargo.toml" \
  --bench sd_jwt_verification -- --baseline main --verbose
```

Run the baseline first, then the feature revision, and repeat in reverse order
before claiming a change. Record median time, the 95% confidence interval, and
credentials per second for every benchmark ID. Do not commit Criterion output
or accept a speedup when the reverse-order repeat contradicts the first run.

## Same-HEAD serial versus parallel comparison

Use this comparison to isolate the `parallel` feature on one exact source tree.
The serial build explicitly disables all default features; the parallel build
uses the same flags plus `--features parallel`. Each order has a fresh Criterion
home, a uniquely named baseline, and separate Cargo target directories. The
scripts leave results and build artifacts under the printed run root for review,
but restore the caller's environment even when a command fails.

Do not compare results from different commits or from a working tree that
changes during the run. A dirty tree is recorded rather than silently treated as
the named commit; prefer a clean tree for evidence intended to be shared.

PowerShell:

```powershell
$repo = git rev-parse --show-toplevel
if ($LASTEXITCODE -ne 0) { throw "Run this inside the benchmark repository" }

$runTag = "$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))-$PID"
$runRoot = Join-Path ([System.IO.Path]::GetTempPath()) "sd-jwt-verification-$runTag"
$serialToParallelHome = Join-Path $runRoot "criterion-serial-to-parallel"
$parallelToSerialHome = Join-Path $runRoot "criterion-parallel-to-serial"
$serialToParallelBaseline = "serial-a-to-b-$runTag"
$parallelToSerialBaseline = "parallel-b-to-a-$runTag"

if (Test-Path -LiteralPath $runRoot) {
    throw "Fresh run root already exists: $runRoot"
}

$headBefore = git -C $repo rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw "Could not resolve HEAD" }
$dirtyBefore = ((git -C $repo status --porcelain=v1 --untracked-files=all | Out-String).TrimEnd())
if ($LASTEXITCODE -ne 0) { throw "Could not record working-tree state" }

$oldCriterionHome = [Environment]::GetEnvironmentVariable("CRITERION_HOME", "Process")
$oldCargoTargetDir = [Environment]::GetEnvironmentVariable("CARGO_TARGET_DIR", "Process")

try {
    # A -> B: serial feature-off baseline, then parallel feature-on comparison.
    $env:CRITERION_HOME = $serialToParallelHome
    $env:CARGO_TARGET_DIR = Join-Path $runRoot "target-a-to-b-serial"
    cargo bench --locked --manifest-path "$repo\Cargo.toml" --no-default-features --bench sd_jwt_verification -- --save-baseline $serialToParallelBaseline --verbose
    if ($LASTEXITCODE -ne 0) { throw "A-to-B serial baseline failed" }

    $env:CARGO_TARGET_DIR = Join-Path $runRoot "target-a-to-b-parallel"
    cargo bench --locked --manifest-path "$repo\Cargo.toml" --no-default-features --features parallel --bench sd_jwt_verification -- --baseline $serialToParallelBaseline --verbose
    if ($LASTEXITCODE -ne 0) { throw "A-to-B parallel comparison failed" }

    # B -> A: parallel feature-on baseline, then serial feature-off comparison.
    $env:CRITERION_HOME = $parallelToSerialHome
    $env:CARGO_TARGET_DIR = Join-Path $runRoot "target-b-to-a-parallel"
    cargo bench --locked --manifest-path "$repo\Cargo.toml" --no-default-features --features parallel --bench sd_jwt_verification -- --save-baseline $parallelToSerialBaseline --verbose
    if ($LASTEXITCODE -ne 0) { throw "B-to-A parallel baseline failed" }

    $env:CARGO_TARGET_DIR = Join-Path $runRoot "target-b-to-a-serial"
    cargo bench --locked --manifest-path "$repo\Cargo.toml" --no-default-features --bench sd_jwt_verification -- --baseline $parallelToSerialBaseline --verbose
    if ($LASTEXITCODE -ne 0) { throw "B-to-A serial comparison failed" }

    $headAfter = git -C $repo rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { throw "Could not re-check HEAD" }
    $dirtyAfter = ((git -C $repo status --porcelain=v1 --untracked-files=all | Out-String).TrimEnd())
    if ($LASTEXITCODE -ne 0) { throw "Could not re-check working-tree state" }
    if ($headAfter -ne $headBefore -or $dirtyAfter -ne $dirtyBefore) {
        throw "HEAD or working-tree state changed during the comparison"
    }

    Write-Output "Run root: $runRoot"
    Write-Output "HEAD: $headBefore"
    Write-Output "Dirty state: $(if ($dirtyBefore) { $dirtyBefore } else { '<clean>' })"
    Write-Output "A-to-B baseline: $serialToParallelBaseline"
    Write-Output "B-to-A baseline: $parallelToSerialBaseline"
} finally {
    [Environment]::SetEnvironmentVariable("CRITERION_HOME", $oldCriterionHome, "Process")
    [Environment]::SetEnvironmentVariable("CARGO_TARGET_DIR", $oldCargoTargetDir, "Process")
}
```

POSIX shell:

```sh
set -eu

repo=$(git rev-parse --show-toplevel)
run_tag="$(date -u +%Y%m%dT%H%M%SZ)-$$"
run_root="${TMPDIR:-/tmp}/sd-jwt-verification-$run_tag"
serial_to_parallel_home="$run_root/criterion-serial-to-parallel"
parallel_to_serial_home="$run_root/criterion-parallel-to-serial"
serial_to_parallel_baseline="serial-a-to-b-$run_tag"
parallel_to_serial_baseline="parallel-b-to-a-$run_tag"

if [ -e "$run_root" ]; then
  echo "Fresh run root already exists: $run_root" >&2
  exit 1
fi

head_before=$(git -C "$repo" rev-parse HEAD)
dirty_before=$(git -C "$repo" status --porcelain=v1 --untracked-files=all)
old_criterion_home_is_set=${CRITERION_HOME+x}
old_criterion_home=${CRITERION_HOME-}
old_cargo_target_dir_is_set=${CARGO_TARGET_DIR+x}
old_cargo_target_dir=${CARGO_TARGET_DIR-}

cleanup_same_head() {
  status=$?
  trap - 0 1 2 15
  if [ "$old_criterion_home_is_set" = x ]; then
    export CRITERION_HOME="$old_criterion_home"
  else
    unset CRITERION_HOME
  fi
  if [ "$old_cargo_target_dir_is_set" = x ]; then
    export CARGO_TARGET_DIR="$old_cargo_target_dir"
  else
    unset CARGO_TARGET_DIR
  fi
  exit "$status"
}
trap cleanup_same_head 0
trap 'exit 130' 1 2 15

# A -> B: serial feature-off baseline, then parallel feature-on comparison.
export CRITERION_HOME=$serial_to_parallel_home
export CARGO_TARGET_DIR="$run_root/target-a-to-b-serial"
cargo bench --locked --manifest-path "$repo/Cargo.toml" \
  --no-default-features --bench sd_jwt_verification -- \
  --save-baseline "$serial_to_parallel_baseline" --verbose

export CARGO_TARGET_DIR="$run_root/target-a-to-b-parallel"
cargo bench --locked --manifest-path "$repo/Cargo.toml" \
  --no-default-features --features parallel --bench sd_jwt_verification -- \
  --baseline "$serial_to_parallel_baseline" --verbose

# B -> A: parallel feature-on baseline, then serial feature-off comparison.
export CRITERION_HOME=$parallel_to_serial_home
export CARGO_TARGET_DIR="$run_root/target-b-to-a-parallel"
cargo bench --locked --manifest-path "$repo/Cargo.toml" \
  --no-default-features --features parallel --bench sd_jwt_verification -- \
  --save-baseline "$parallel_to_serial_baseline" --verbose

export CARGO_TARGET_DIR="$run_root/target-b-to-a-serial"
cargo bench --locked --manifest-path "$repo/Cargo.toml" \
  --no-default-features --bench sd_jwt_verification -- \
  --baseline "$parallel_to_serial_baseline" --verbose

head_after=$(git -C "$repo" rev-parse HEAD)
dirty_after=$(git -C "$repo" status --porcelain=v1 --untracked-files=all)
if [ "$head_after" != "$head_before" ] || [ "$dirty_after" != "$dirty_before" ]; then
  echo "HEAD or working-tree state changed during the comparison" >&2
  exit 1
fi

printf 'Run root: %s\n' "$run_root"
printf 'HEAD: %s\n' "$head_before"
if [ -n "$dirty_before" ]; then
  printf 'Dirty state:\n%s\n' "$dirty_before"
else
  printf 'Dirty state: <clean>\n'
fi
printf 'A-to-B baseline: %s\n' "$serial_to_parallel_baseline"
printf 'B-to-A baseline: %s\n' "$parallel_to_serial_baseline"
```

Criterion reports each comparison relative to the baseline that ran first. The
B-to-A percentage therefore has the opposite direction from A-to-B. Normalize
both deltas to parallel relative to serial before checking whether order changed
the conclusion. Do not combine the two Criterion homes or reuse either name for
a later run.

## Evidence record

Keep the following with any performance conclusion; do not fill gaps with
assumptions or results from another run:

- Exact repository HEAD, complete dirty-state output, lockfile hash, full Cargo
  and Criterion flags, run order, Criterion home and baseline names, and SHA-256
  hashes of all four benchmark executables.
- OS and version, CPU model and logical topology, available RAM, power profile,
  thermal/idle controls, `rustc -Vv`, `cargo -V`, and compilation target triple.
- The value returned by `std::thread::available_parallelism()`, the selected
  worker count, and the tested SHA's `PARALLEL_MIN_DISCLOSURES`,
  `PARALLEL_MIN_TOTAL_ENCODED_BYTES`, and `MAX_PARALLEL_WORKERS` constants.
- For every benchmark ID, the actual presented-disclosure count, total encoded
  disclosure bytes, and selected serial or native-parallel route. If the harness
  does not expose these fields, mark route-specific evidence incomplete rather
  than inferring that `--features parallel` necessarily selected parallel work.
- Criterion estimator, sample size, warm-up and measurement times, confidence
  level and interval, median/mean or slope as applicable, credentials/second,
  and the normalized parallel-versus-serial delta for both run orders.
- Exact correctness-gate commands and outcomes for feature-off tests,
  `--features parallel` tests, both benchmark smoke modes, and the WASM serial
  fallback check when a WASM claim is in scope.
