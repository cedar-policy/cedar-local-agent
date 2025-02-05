use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
use cedar_local_agent::public::file::{entity_provider, policy_set_provider};
use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};
use cedar_policy::{Context, Decision, Entities, Request};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use futures::executor::block_on;
use std::sync::Arc;

fn construct_request() -> Request {
    Request::new(
        "Principal::\"request\"".parse().unwrap(),
        "Action::\"request\"".parse().unwrap(),
        "Resource::\"request\"".parse().unwrap(),
        Context::empty(),
        None,
    )
    .unwrap()
}

fn construct_authorizer(num_policies: u32) -> Authorizer<PolicySetProvider, EntityProvider> {
    let policy_set_provider = Arc::new(
        PolicySetProvider::new(
            policy_set_provider::ConfigBuilder::default()
                .policy_set_path(format!("benches/data/{}.cedar", num_policies))
                .build()
                .unwrap(),
        )
        .unwrap(),
    );

    let entity_provider = Arc::new(
        EntityProvider::new(
            entity_provider::ConfigBuilder::default()
                .entities_path(format!("benches/data/{}.entities.json", num_policies))
                .build()
                .unwrap(),
        )
        .unwrap(),
    );

    Authorizer::new(
        AuthorizerConfigBuilder::default()
            .entity_provider(entity_provider)
            .policy_set_provider(policy_set_provider)
            .build()
            .unwrap(),
    )
}

fn validate_request(authorizer: &Authorizer<PolicySetProvider, EntityProvider>, request: &Request) {
    let response = block_on(async {
        authorizer
            .is_authorized(request, &Entities::empty())
            .await
            .unwrap()
    });
    assert_eq!(response.decision(), Decision::Allow);
}

const NUM_POLICIES_ARR: [u32; 3] = [10, 100, 1000];

fn is_authorized_benchmark(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("is_authorized");
    for i in NUM_POLICIES_ARR.iter() {
        let authorizer: Authorizer<PolicySetProvider, EntityProvider> = construct_authorizer(*i);
        let request = construct_request();
        validate_request(&authorizer, &request);

        let input = (request, Entities::empty());
        bench_group.bench_with_input(BenchmarkId::from_parameter(i), &input, |b, i| {
            let (request, entities) = i;
            b.to_async(tokio::runtime::Runtime::new().unwrap())
                .iter(|| async { authorizer.is_authorized(request, entities).await.unwrap() })
        });
    }
}

#[cfg(feature = "partial-eval")]
fn is_authorized_partial_benchmark(c: &mut Criterion) {
    let mut bench_group = c.benchmark_group("is_authorized_partial");
    for i in NUM_POLICIES_ARR.iter() {
        let authorizer: Authorizer<PolicySetProvider, EntityProvider> = construct_authorizer(*i);
        let request = construct_request();
        validate_request(&authorizer, &request);

        let input = (request, Entities::empty());
        bench_group.bench_with_input(BenchmarkId::from_parameter(i), &input, |b, i| {
            let (request, entities) = i;
            b.to_async(tokio::runtime::Runtime::new().unwrap())
                .iter(|| async {
                    authorizer
                        .is_authorized_partial(request, entities)
                        .await
                        .unwrap()
                })
        });
    }
}

#[cfg(not(feature = "partial-eval"))]
criterion_group!(benches, is_authorized_benchmark);
#[cfg(feature = "partial-eval")]
criterion_group!(
    benches,
    is_authorized_benchmark,
    is_authorized_partial_benchmark
);
criterion_main!(benches);
