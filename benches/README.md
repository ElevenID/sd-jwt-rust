# SD-JWT verification benchmark

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
$baseCommit = "origin/main"
$harnessCommit = "<full 40-character SHA of the benchmark-only harness commit>"
$oldCriterionHome = [Environment]::GetEnvironmentVariable("CRITERION_HOME", "Process")
$oldCargoTargetDir = [Environment]::GetEnvironmentVariable("CARGO_TARGET_DIR", "Process")
$baselineAdded = $false

if ($harnessCommit -notmatch '^[0-9a-fA-F]{40}$') {
    throw "Set harnessCommit to the exact full benchmark-harness commit SHA"
}
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
base_commit=origin/main
harness_commit='<full 40-character SHA of the benchmark-only harness commit>'
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
