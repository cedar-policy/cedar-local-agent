use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
use cedar_local_agent::public::file::{entity_provider, policy_set_provider};
use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};
use cedar_policy::{Context, Entities, Request};
use cedar_policy_core::authorizer::Decision;
use std::sync::Arc;

fn construct_request() -> Request {
    Request::new(
        Some("Principal::\"request\"".parse().unwrap()),
        Some("Action::\"request\"".parse().unwrap()),
        Some("Resource::\"request\"".parse().unwrap()),
        Context::empty(),
        None,
    )
    .unwrap()
}

#[inline]
fn construct_authorizer() -> Authorizer<PolicySetProvider, EntityProvider> {
    let policy_set_provider = Arc::new(
        PolicySetProvider::new(
            policy_set_provider::ConfigBuilder::default()
                .policy_set_path("examples/simple/simple.cedar")
                .build()
                .unwrap(),
        )
        .unwrap(),
    );

    let entity_provider = Arc::new(
        EntityProvider::new(
            entity_provider::ConfigBuilder::default()
                .entities_path("examples/simple/simple.entities.json")
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

/// Create dataset with `cargo run --bin data_gen -- simple <number of policies>`
///
/// You can use `cargo flamegraph --example simple_large_data --root --freq 5000` to profile this function.
/// You'll need to have `cargo-flamegraph` installed.
#[tokio::main]
async fn main() {
    let authorizer = construct_authorizer();
    let request = construct_request();

    let response = authorizer
        .is_authorized(&request, &Entities::empty())
        .await
        .unwrap();

    println!("{:?}", response);
    assert_eq!(response.decision(), Decision::Allow);
}
