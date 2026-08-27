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
