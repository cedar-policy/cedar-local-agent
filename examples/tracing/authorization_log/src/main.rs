use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use std::sync::Arc;

use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
use cedar_local_agent::public::file::{entity_provider, policy_set_provider};
use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};
use cedar_policy::{Context, Entities, Request};
use cedar_policy_core::authorizer::Decision;

use cedar_local_agent::public::log::event::{AuthorizerFormatter,AuthorizerTarget};

#[tokio::main]
pub async fn main() {
    /*
     * Initialize the tracing logger in the `main` function before starting your server or beginning operational processes
     */

    // Example of creating a new log file in the format of output/tracing_example_logs/authorization.log.yyyy-MM-dd-HH-mm minutely
    let authorization_roller = tracing_appender::rolling::minutely("output/tracing_example_logs", "authorization.log");
    let (authorization_non_blocking, _authorization_guard) =
        tracing_appender::non_blocking(authorization_roller);
    let authorization_log_layer = tracing_subscriber::fmt::layer()
        .event_format(AuthorizerFormatter(AuthorizerTarget::Simple))
        .with_writer(authorization_non_blocking);
   
    // Initialize the tracing logger with the tracing layer
    tracing_subscriber::registry()
        .with(authorization_log_layer)
        .try_init()
        .expect("Logging Failed to Start, Exiting.");

    /*
     * Start your authorizer
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

    /*
     * Send the cedar request to the authorizer and assert the result
     */
    assert_eq!(
        authorizer
            .is_authorized(
                &Request::new(
                    Some(format!("User::\"Cedar\"").parse().unwrap()),
                    Some(format!("Action::\"read\"").parse().unwrap()),
                    Some(format!("Box::\"3\"").parse().unwrap()),
                    Context::empty(),
                ),
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