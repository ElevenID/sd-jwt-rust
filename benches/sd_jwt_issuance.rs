// Copyright (c) 2024 DSR Corporation, Denver, Colorado.
// https://www.dsr-corporation.com
// SPDX-License-Identifier: Apache-2.0

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use jsonwebtoken::EncodingKey;
use sd_jwt_rs::issuer::issuance_benchmark::{
    issuance_benchmark_cases, prepare_issuance_route_sink_from_env, IssuanceBenchmarkFixture,
    IssuanceBenchmarkRoute, IssuanceBenchmarkRouteRecord, IssuanceBenchmarkStage,
    ISSUANCE_BENCHMARK_GROUP_ID, ISSUANCE_BENCHMARK_ID_COUNT,
};

const PRIVATE_ISSUER_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgUr2bNKuBPOrAaxsR\nnbSH6hIhmNTxSGXshDSUD1a1y7ihRANCAARvbx3gzBkyPDz7TQIbjF+ef1IsxUwz\nX1KWpmlVv+421F7+c1sLqGk4HUuoVeN8iOoAcE547pJhUEJyf5Asc6pP\n-----END PRIVATE KEY-----\n";

fn benchmark_issuance(c: &mut Criterion) {
    let route_sink = prepare_issuance_route_sink_from_env()
        .expect("issuance route evidence destination must be an absolute new file");
    let mut route_records = Vec::with_capacity(ISSUANCE_BENCHMARK_ID_COUNT);
    let mut group = c.benchmark_group(ISSUANCE_BENCHMARK_GROUP_ID);
    let issuer_key = EncodingKey::from_ec_pem(PRIVATE_ISSUER_PEM.as_bytes())
        .expect("benchmark issuer key must be valid");

    for case in issuance_benchmark_cases() {
        let fixture = IssuanceBenchmarkFixture::new(case, issuer_key.clone(), "ES256".to_owned())
            .expect("issuance benchmark fixture construction must succeed");
        let preflight = fixture
            .preflight()
            .expect("serial/candidate issuance preflight must succeed");

        // One untimed compact JSON record binds each exact Criterion ID to the
        // route observed at that same stage's preflight boundary. Records stay
        // out of Criterion's stdout and all timed closures.
        for (stage, candidate_route) in [
            (
                IssuanceBenchmarkStage::ExecutorAssembly,
                preflight.executor_candidate_route(),
            ),
            (
                IssuanceBenchmarkStage::FullIssuance,
                preflight.full_candidate_route(),
            ),
        ] {
            route_records
                .push(IssuanceBenchmarkRouteRecord::serial_oracle().machine_record(case, stage));
            route_records.push(candidate_route.machine_record(case, stage));
        }

        for route in [
            IssuanceBenchmarkRoute::SerialOracle,
            IssuanceBenchmarkRoute::AdaptiveCandidate,
        ] {
            group.throughput(Throughput::Bytes(
                u64::try_from(fixture.input_bytes(IssuanceBenchmarkStage::ExecutorAssembly))
                    .expect("fixture size must fit u64"),
            ));
            group.bench_function(
                case.benchmark_id(IssuanceBenchmarkStage::ExecutorAssembly, route),
                |b| {
                    b.iter_batched(
                        || {
                            fixture
                                .prepare_executor()
                                .expect("issuance plan construction must succeed")
                        },
                        |prepared| {
                            black_box(
                                prepared
                                    .execute(black_box(route))
                                    .expect("issuance executor benchmark must succeed"),
                            )
                        },
                        BatchSize::LargeInput,
                    );
                },
            );

            group.throughput(Throughput::Bytes(
                u64::try_from(fixture.input_bytes(IssuanceBenchmarkStage::FullIssuance))
                    .expect("fixture size must fit u64"),
            ));
            group.bench_function(
                case.benchmark_id(IssuanceBenchmarkStage::FullIssuance, route),
                |b| {
                    b.iter_batched(
                        || fixture.prepare_full_issuance(),
                        |prepared| {
                            black_box(
                                prepared
                                    .execute(black_box(route))
                                    .expect("full issuance benchmark must succeed"),
                            )
                        },
                        BatchSize::LargeInput,
                    );
                },
            );
        }
    }

    if let Some(route_sink) = route_sink {
        route_sink
            .finish(&route_records)
            .expect("issuance route evidence must be complete and durable");
    }

    group.finish();
}

criterion_group!(benches, benchmark_issuance);
criterion_main!(benches);
