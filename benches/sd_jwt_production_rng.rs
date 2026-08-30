// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

#[cfg(not(feature = "mock_salts"))]
use criterion::{black_box, BatchSize, Throughput};
use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(not(feature = "mock_salts"))]
use jsonwebtoken::EncodingKey;
#[cfg(not(feature = "mock_salts"))]
use sd_jwt_rs::issuer::ClaimsForSelectiveDisclosureStrategy;
#[cfg(not(feature = "mock_salts"))]
use sd_jwt_rs::{SDJWTIssuer, SDJWTSerializationFormat};
#[cfg(not(feature = "mock_salts"))]
use serde_json::{Map, Value};

#[cfg(not(feature = "mock_salts"))]
const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";

#[cfg(not(feature = "mock_salts"))]
fn claims(count: usize) -> Value {
    let mut claims = Map::with_capacity(count);
    for ordinal in 0..count {
        claims.insert(format!("claim_{ordinal:04}"), Value::from(ordinal as u64));
    }
    Value::Object(claims)
}

#[cfg(not(feature = "mock_salts"))]
fn benchmark_production_rng(c: &mut Criterion) {
    let claims = claims(512);
    let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes())
        .expect("benchmark issuer key must be valid");
    let mut issuer = SDJWTIssuer::new(issuer_key, None);
    let mut group = c.benchmark_group("sd_jwt_production_rng");
    group.throughput(Throughput::Elements(1));
    group.bench_function("top_level_512_disclosures_with_decoys", |b| {
        b.iter_batched(
            || claims.clone(),
            |claims| {
                black_box(
                    issuer
                        .issue_sd_jwt(
                            claims,
                            ClaimsForSelectiveDisclosureStrategy::TopLevel,
                            None,
                            true,
                            SDJWTSerializationFormat::Compact,
                        )
                        .expect("production-randomness benchmark issuance must succeed"),
                )
            },
            BatchSize::LargeInput,
        );
    });
    group.finish();
}

#[cfg(feature = "mock_salts")]
fn benchmark_production_rng(_: &mut Criterion) {}

criterion_group!(benches, benchmark_production_rng);
criterion_main!(benches);
