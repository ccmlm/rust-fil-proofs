use criterion::{black_box, criterion_group, criterion_main, Criterion};
use filecoin_hashers::{halo, poseidon::PoseidonHasher};
use pasta_curves::{Fp, Fq};
use storage_proofs_core::{
    api_version::ApiVersion,
    drgraph::{BucketGraph, Graph, BASE_DEGREE},
};

// DRG parent-gen for the first and second nodes (node-indexes `0` and `1`) is different than
// parent-gen for all other nodes (node-indexes `>= 2`).
const CHILD_NODE: usize = 2;

#[allow(clippy::unit_arg)]
fn drgraph(c: &mut Criterion) {
    let nodes = vec![12, 24, 128, 1024];

    let mut group = c.benchmark_group("drg-parent-gen");
    for n in nodes {
        group.bench_function(format!("deg={}-nodes={}-bls12", BASE_DEGREE, n), |b| {
            let graph =
                BucketGraph::<PoseidonHasher>::new(n, BASE_DEGREE, 0, [32; 32], ApiVersion::V1_1_0)
                    .unwrap();

            b.iter(|| {
                let mut parents = vec![0; BASE_DEGREE];
                black_box(graph.parents(CHILD_NODE, &mut parents).unwrap());
            })
        });
    }

    group.finish();
}

#[allow(clippy::unit_arg)]
fn drgraph_halo(c: &mut Criterion) {
    let nodes = vec![12, 24, 128, 1024];

    let mut group = c.benchmark_group("drg-parent-gen");

    for n in &nodes {
        group.bench_function(format!("deg={}-nodes={}-pallas", BASE_DEGREE, n), |b| {
            let graph = BucketGraph::<halo::PoseidonHasher<Fp>>::new(
                *n,
                BASE_DEGREE,
                0,
                [32; 32],
                ApiVersion::V1_1_0,
            )
            .unwrap();

            b.iter(|| {
                let mut parents = vec![0; BASE_DEGREE];
                black_box(graph.parents(CHILD_NODE, &mut parents).unwrap());
            })
        });
    }

    for n in nodes {
        group.bench_function(format!("deg={}-nodes={}-vesta", BASE_DEGREE, n), |b| {
            let graph = BucketGraph::<halo::PoseidonHasher<Fq>>::new(
                n,
                BASE_DEGREE,
                0,
                [32; 32],
                ApiVersion::V1_1_0,
            )
            .unwrap();

            b.iter(|| {
                let mut parents = vec![0; BASE_DEGREE];
                black_box(graph.parents(CHILD_NODE, &mut parents).unwrap());
            })
        });
    }

    group.finish();
}

criterion_group!(benches, drgraph, drgraph_halo);
criterion_main!(benches);
