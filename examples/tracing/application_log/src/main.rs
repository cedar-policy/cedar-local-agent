use tracing_core::Level;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

use std::sync::Arc;

use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
use cedar_local_agent::public::file::{entity_provider, policy_set_provider};
use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};
use cedar_policy::{Context, Decision, Entities, Request};

#[tokio::main]
pub async fn main() {
    /*
     * Initialize the tracing logger in the `main` function before starting your server or beginning operational processes
     */

    // Example of creating a new log file in the format of output/tracing_example_logs/application.log.yyyy-MM-dd-HH-mm minutely
    let roller =
        tracing_appender::rolling::minutely("output/tracing_example_logs", "application.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(roller);

    // Example of create a filter that only logs INFO level messages from the `cedar_local_agent` crate
    let filter =
        tracing_subscriber::filter::Targets::new().with_target("cedar_local_agent", Level::INFO);

    // Example of creating a tracing layer that logs to a file in json format
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(non_blocking)
        .with_filter(filter);

    // Initialize the tracing logger with the tracing layer
    tracing_subscriber::registry()
        .with(layer)
        .try_init()
        .expect("Logging Failed to Start, Exiting.");

    /*
     * Start your server or operational logic here
     */
    let policy_set_provider = PolicySetProvider::new(
        policy_set_provider::ConfigBuilder::default()
            .policy_set_path("../../../tests/data/sweets.cedar")
            .build()
            .unwrap(),
    )
    .unwrap();

    let entity_provider = EntityProvider::new(
        entity_provider::ConfigBuilder::default()
            .entities_path("../../../tests/data/sweets.entities.json")
            .schema_path("../../../tests/data/sweets.schema.cedar.json")
            .build()
            .unwrap(),
    )
    .unwrap();

    let authorizer: Authorizer<PolicySetProvider, EntityProvider> = Authorizer::new(
        AuthorizerConfigBuilder::default()
            .entity_provider(Arc::new(entity_provider))
            .policy_set_provider(Arc::new(policy_set_provider))
            .build()
            .unwrap(),
    );

    assert_eq!(
        authorizer
            .is_authorized(
                &Request::new(
                    Some(format!("User::\"Cedar\"").parse().unwrap()),
                    Some(format!("Action::\"read\"").parse().unwrap()),
                    Some(format!("Box::\"3\"").parse().unwrap()),
                    Context::empty(),
                    None,
                )
                .unwrap(),
                &Entities::empty()
            )
            .await
            .unwrap()
            .decision(),
        Decision::Deny
    )
}

// For more information on tracing and its structured logging and diagnostics, visit:
// https://docs.rs/tracing/latest/tracing/
// To learn more about setting up different subscribers and writers. We recommend using tracing-specific libraries, such as:
// https://tracing.rs/tracing_subscriber/index.html
// https://tracing.rs/tracing_appender/index.html
