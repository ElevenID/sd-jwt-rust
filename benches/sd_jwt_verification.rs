// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use jsonwebtoken::{DecodingKey, EncodingKey};
use sd_jwt_rs::{
    ClaimsForSelectiveDisclosureStrategy, SDJWTIssuer, SDJWTSerializationFormat, SDJWTVerifier,
    MAX_SD_JWT_DISCLOSURE_BYTES, MAX_SD_JWT_INPUT_BYTES,
};
use serde_json::{json, Map, Value};

const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";
const PUBLIC_ISSUER_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb28d4MwZMjw8+00CG4xfnn9SLMVM\nM19SlqZpVb/uNtRe/nNbC6hpOB1LqFXjfIjqAHBOeO6SYVBCcn+QLHOqTw==\n-----END PUBLIC KEY-----\n";
const DISCLOSURE_COUNTS: [usize; 5] = [1, 8, 32, 128, 512];
// Keep the aggregate raw value data large enough to exercise the byte gate while
// leaving room for JSON, Base64url, the issuer JWT, and compact separators.
const TARGET_LARGE_RAW_BYTES: usize = MAX_SD_JWT_INPUT_BYTES / 2;
// Base64url expands by roughly 4/3 and each disclosure also carries its salt and
// claim name. Half the encoded limit is therefore an intentionally conservative
// per-value ceiling.
const MAX_LARGE_VALUE_BYTES: usize = MAX_SD_JWT_DISCLOSURE_BYTES / 2;

#[cfg(feature = "mock_salts")]
fn seed_benchmark_salts() {
    let mut salts = sd_jwt_rs::utils::SALTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    salts.clear();
    salts.extend((0..4096).map(|ordinal| format!("benchmark-salt-{ordinal:04}")));
}

#[cfg(not(feature = "mock_salts"))]
fn seed_benchmark_salts() {}

#[derive(Clone, Copy)]
enum PayloadClass {
    Small,
    Medium,
    Large,
    Mixed,
}

impl PayloadClass {
    fn label(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large_bounded",
            Self::Mixed => "mixed",
        }
    }

    fn value(self, ordinal: usize, large_payload_bytes: usize) -> Value {
        match self {
            Self::Small => small_value(ordinal),
            Self::Medium => medium_value(ordinal),
            Self::Large => large_value(ordinal, large_payload_bytes),
            Self::Mixed => match ordinal % 3 {
                0 => small_value(ordinal),
                1 => medium_value(ordinal),
                _ => large_value(ordinal, large_payload_bytes),
            },
        }
    }

    fn large_value_count(self, disclosure_count: usize) -> usize {
        match self {
            Self::Large => disclosure_count,
            Self::Mixed => (0..disclosure_count)
                .filter(|ordinal| ordinal % 3 == 2)
                .count(),
            Self::Small | Self::Medium => 0,
        }
    }
}

fn small_value(ordinal: usize) -> Value {
    Value::String(format!("value-{ordinal}"))
}

fn medium_value(ordinal: usize) -> Value {
    json!({
        "ordinal": ordinal,
        "profile": {
            "active": ordinal.is_multiple_of(2),
            "display_name": format!("Credential subject {ordinal}"),
            "notes": "medium-payload-".repeat(64),
        },
        "roles": ["holder", "member", "verified"],
    })
}

fn large_value(ordinal: usize, payload_bytes: usize) -> Value {
    let suffix = format!("-{ordinal}");
    let body_length = payload_bytes.saturating_sub(suffix.len());
    Value::String(format!("{}{suffix}", "L".repeat(body_length)))
}

fn claims(disclosure_count: usize, payload_class: PayloadClass) -> Value {
    let large_value_count = payload_class.large_value_count(disclosure_count);
    let large_payload_bytes = TARGET_LARGE_RAW_BYTES
        .checked_div(large_value_count)
        .unwrap_or(0)
        .min(MAX_LARGE_VALUE_BYTES);
    let mut claims = Map::new();
    claims.insert(
        "iss".to_string(),
        Value::String("https://issuer.example.com".to_string()),
    );
    claims.insert("iat".to_string(), Value::from(1_700_000_000_i64));

    for ordinal in 0..disclosure_count {
        claims.insert(
            format!("claim_{ordinal:04}"),
            payload_class.value(ordinal, large_payload_bytes),
        );
    }

    Value::Object(claims)
}

fn issue_fixture(disclosure_count: usize, payload_class: PayloadClass) -> String {
    let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes())
        .expect("benchmark issuer key must be valid");
    let mut issuer = SDJWTIssuer::new(issuer_key, Some("ES256".to_string()));
    let presentation = issuer
        .issue_sd_jwt(
            claims(disclosure_count, payload_class),
            ClaimsForSelectiveDisclosureStrategy::TopLevel,
            None,
            false,
            SDJWTSerializationFormat::Compact,
        )
        .expect("benchmark fixture issuance must succeed");

    let segments = presentation.split('~').count();
    assert_eq!(segments, disclosure_count + 2);
    assert!(
        presentation.len() <= MAX_SD_JWT_INPUT_BYTES,
        "benchmark fixture exceeds the public presentation limit"
    );
    assert!(
        presentation
            .split('~')
            .skip(1)
            .take(disclosure_count)
            .all(|disclosure| disclosure.len() <= MAX_SD_JWT_DISCLOSURE_BYTES),
        "benchmark fixture exceeds the public disclosure limit"
    );
    presentation
}

fn verify(presentation: String, issuer_key: DecodingKey) -> Value {
    SDJWTVerifier::new(
        presentation,
        Box::new(move |_, _| issuer_key.clone()),
        None,
        None,
        SDJWTSerializationFormat::Compact,
    )
    .expect("benchmark fixture verification must succeed")
    .verified_claims
}

fn benchmark_verification(c: &mut Criterion) {
    seed_benchmark_salts();

    let payload_classes = [
        PayloadClass::Small,
        PayloadClass::Medium,
        PayloadClass::Large,
        PayloadClass::Mixed,
    ];
    let mut group = c.benchmark_group("sd_jwt_verification");
    group.throughput(Throughput::Elements(1));

    for payload_class in payload_classes {
        for disclosure_count in DISCLOSURE_COUNTS {
            // Fixture construction, disclosure salts, and issuer signing are deliberately
            // outside the timed iteration. The verifier still performs compact parsing,
            // disclosure decoding, JSON parsing, hashing, signature verification, duplicate
            // checks, and recursive claim reconstruction on every measured invocation.
            let presentation = issue_fixture(disclosure_count, payload_class);
            let issuer_key = DecodingKey::from_ec_pem(PUBLIC_ISSUER_PEM.as_bytes())
                .expect("benchmark issuer public key must be valid");

            let verified = verify(presentation.clone(), issuer_key.clone());
            assert_eq!(
                verified
                    .as_object()
                    .expect("verified claims must be an object")
                    .len(),
                disclosure_count + 2
            );

            group.bench_with_input(
                BenchmarkId::new(payload_class.label(), disclosure_count),
                &disclosure_count,
                |b, _| {
                    b.iter_batched(
                        || (presentation.clone(), issuer_key.clone()),
                        |(presentation, issuer_key)| {
                            black_box(verify(black_box(presentation), issuer_key))
                        },
                        BatchSize::LargeInput,
                    );
                },
            );
        }
    }

    group.finish();
}

criterion_group!(benches, benchmark_verification);
criterion_main!(benches);
