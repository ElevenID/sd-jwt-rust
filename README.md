# SD-JWT Rust Reference Implementation

This is the reference implementation of the [IETF SD-JWT specification](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) written in Rust.
Supported version: 7.

Note: while the project is started as a reference implementation, it is intended to be evolved to a production-ready, high-performance implementations in the long-run.

## API
Note: the current version of the crate is 0.0.x, so the API should be considered as experimental.
Proposals about API improvements are highly appreciated.

```rust
fn demo() {
    let mut issuer = SDJWTIssuer::new(issuer_key, None);
    let sd_jwt = issuer.issue_sd_jwt(claims, ClaimsForSelectiveDisclosureStrategy::AllLevels, holder_key, add_decoy, SDJWTSerializationFormat::Compact).unwrap();

    let mut holder = SDJWTHolder::new(sd_jwt, SDJWTSerializationFormat::Compact, Box::new(cb_to_resolve_issuer_key)).unwrap();
    let presentation = holder.create_presentation(claims_to_disclosure, None, None, None, None).unwrap();

    let verified_claims = SDJWTVerifier::new(presentation, Box::new(cb_to_resolve_issuer_key), None, None, SDJWTSerializationFormat::Compact).unwrap()
                            .verified_claims;
}
```

See `tests/demos.rs` for more details;

## Repository structure

### SD-JWT Rust crate
SD-JWT crate is the root of the repository.

To build the project simply perform:
```shell
cargo build
```

To run tests:
```shell
cargo test
```

### Issuance qualification evidence

The opt-in `issuance_bench` feature exposes a deterministic qualification
manifest without enabling the production adaptive route:

```shell
cargo run --features issuance_bench --example issuance_qualification_manifest -- --output /absolute/new/manifest.json
```

The output path must be absolute and must not already exist. A frozen
qualification invocation sets both `SD_JWT_ISSUANCE_ROUTE_BENCHMARK_ID` to one
exact full Criterion ID and `SD_JWT_ISSUANCE_ROUTE_NDJSON` to a different
absolute, nonexistent file. The harness constructs and validates all 132
preflight records in canonical registration order, then writes only the
selected compact record plus one LF. The artifact is capped at 1 MiB, flushed,
and durably synced. Supplying only one variable, using a noncanonical selector,
or changing the frozen Criterion arguments fails closed. When both variables
are absent, no route-evidence file is created.

The fixed qualification binary also supports the optional v3 cooperative
launch barrier. With `MARTY_PERF_START_BARRIER` absent, benchmark startup is
unchanged. With it present, the custom binary entrypoint validates the exact
cleared child environment, coordinate-derived campaign paths, selected ID,
Criterion arguments, canonical token, and installed executable before it
constructs Criterion. The selected ID must also equal the route scheduled for
the token coordinate by the frozen 20-round ABBA/BAAB expansion. It emits the
token-bound canonical ready frame as the first stdout frame, flushes, and blocks
for exactly one canonical release frame terminated by stdin EOF. A matching
release is bound into a create-new,
flushed, durably synced receipt before Criterion construction. Early EOF,
partial, extra, second, noncanonical, oversized, non-UTF-8, or mismatched input
fails closed with a sanitized diagnostic and no Criterion or route activity.
The qualification controller is the trusted exclusive owner of the campaign
root and keeps its directory ancestry unchanged for the child lifetime; the
child's no-follow and handle-identity checks are not a sandbox against a local
actor concurrently replacing an otherwise ordinary parent directory. Such a
mutation violates the quiescent-ancestry assumption and invalidates the
campaign operationally; detecting it is outside the child-side guarantee.
On Unix, receipt durability includes a no-follow parent-directory sync. On
Windows, the child uses `File::sync_all` for file contents and metadata and
does not claim a separate Unix-style parent-directory-entry flush.

### Interoperability testing tool
See [Generate tool README](./generate/README.md) document.

## External Dependencies

Dual license (MIT/Apache 2.0) dependencies: [base64](https://crates.io/crates/base64), [lazy_static](https://crates.io/crates/lazy_static) [log](https://crates.io/crates/log), [serde](https://crates.io/crates/serde), [serde_json](https://crates.io/crates/serde_json), [sha2](https://crates.io/crates/sha2), [rand](https://crates.io/crates/rand), [hmac](https://crates.io/crates/hmac), [thiserror](https://crates.io/crates/thiserror).
MIT license dependencies: [jsonwebtoken](https://crates.io/crates/jsonwebtoken), [strum](https://crates.io/crates/strum)

Note: the list of dependencies may be changed in the future.

## Initial Maintainers

- Sergey Minaev ([Github](https://github.com/jovfer))
- DSR Corporation Decentralized Systems Team ([Github](https://github.com/orgs/DSRCorporation/teams/decentralized-systems))
