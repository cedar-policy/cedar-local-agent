use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use std::sync::Arc;

use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
use cedar_local_agent::public::file::{entity_provider, policy_set_provider};
use cedar_local_agent::public::log;
use cedar_local_agent::public::log::event::{AuthorizerFormatter, AuthorizerTarget};
use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};
use cedar_policy::{Context, Decision, Entities, Request};

#[tokio::main]
pub async fn main() {
    /*
     * Initialize the tracing logger in the `main` function before starting your server or beginning operational processes
     */

    // Example of creating a new log file in the format of output/tracing_example_logs/authorization.log.yyyy-MM-dd-HH-mm minutely
    let authorization_roller =
        tracing_appender::rolling::minutely("output/tracing_example_logs", "authorization.log");
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
     * Initialize the providers with local files
     */
    let policy_set_provider = Arc::new(
        PolicySetProvider::new(
            policy_set_provider::ConfigBuilder::default()
                .policy_set_path("../../../tests/data/sweets.cedar")
                .build()
                .unwrap(),
        )
        .unwrap(),
    );

    let entity_provider = Arc::new(
        EntityProvider::new(
            entity_provider::ConfigBuilder::default()
                .entities_path("../../../tests/data/sweets.entities.json")
                .schema_path("../../../tests/data/sweets.schema.cedar.json")
                .build()
                .unwrap(),
        )
        .unwrap(),
    );

    /*
     * Initialize the Auhtorizers with different configurations
     */

    /*
     * Default log configuration
     * With default log configuration, the authorization logs will be generated in OpenCyberSecurityFramework (OCSF) format
     * and all cedar-related request field (principal, action, resource, context, and entities) which could contian sensitive information would be redacted
     */
    let authorizer_with_no_specified_log_config: Authorizer<PolicySetProvider, EntityProvider> =
        Authorizer::new(
            AuthorizerConfigBuilder::default()
                .entity_provider(entity_provider.clone())
                .policy_set_provider(policy_set_provider.clone())
                // Without specifying the optional log configuration, the default log configuration will be used
                .build()
                .unwrap(),
        );

    let log_config_default = log::ConfigBuilder::default().build().unwrap();
    let authorizer_with_default_log_config: Authorizer<PolicySetProvider, EntityProvider> =
        Authorizer::new(
            AuthorizerConfigBuilder::default()
                .entity_provider(entity_provider.clone())
                .policy_set_provider(policy_set_provider.clone())
                .log_config(log_config_default)
                .build()
                .unwrap(),
        );

    /*
     * Log configuration specifies which request field/fields to be logged
     * With FieldSet specifies whether a field is to be logged, the authorization logs will be generated in OpenCyberSecurityFramework (OCSF) format
     * and certain cedar-related request field (principal, action, resource, context, entities) would be logged, while other fields stay redacted
     */

    // All request fields (principal, action, resource, context, and entities) to be logged
    let log_config_all_fields_to_be_logged = log::ConfigBuilder::default()
        .field_set(
            log::FieldSetBuilder::default()
                .principal(true)
                .action(true)
                .resource(true)
                .context(true)
                .entities(log::FieldLevel::All)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let authorizer_with_all_fields_to_be_logged: Authorizer<PolicySetProvider, EntityProvider> =
        Authorizer::new(
            AuthorizerConfigBuilder::default()
                .entity_provider(entity_provider.clone())
                .policy_set_provider(policy_set_provider.clone())
                .log_config(log_config_all_fields_to_be_logged)
                .build()
                .unwrap(),
        );

    // No field from request entities to be logged
    let log_config_no_field_from_entities_to_be_logged = log::ConfigBuilder::default()
        .field_set(
            log::FieldSetBuilder::default()
                .principal(true)
                .action(true)
                .resource(true)
                .context(true)
                .entities(log::FieldLevel::None)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let authorizer_with_no_field_from_entities_to_be_logged: Authorizer<
        PolicySetProvider,
        EntityProvider,
    > = Authorizer::new(
        AuthorizerConfigBuilder::default()
            .entity_provider(entity_provider.clone())
            .policy_set_provider(policy_set_provider.clone())
            .log_config(log_config_no_field_from_entities_to_be_logged)
            .build()
            .unwrap(),
    );

    /*
     * Initialize an Allow request
     */

    let request = Request::new(
        Some("User::\"Mike\"".to_string().parse().unwrap()),
        Some("Action::\"read\"".to_string().parse().unwrap()),
        Some("Box::\"2\"".to_string().parse().unwrap()),
        Context::empty(),
        None,
    )
    .unwrap();

    // Entities are provided by `entity_provider` above; we don't need more
    let entities = Entities::empty();

    /*
     * Send the cedar request to the authorizers and assert the result
     */
    assert_eq!(
        authorizer_with_no_specified_log_config
            .is_authorized(&request, &entities)
            .await
            .unwrap()
            .decision(),
        Decision::Allow
    );
    assert_eq!(
        authorizer_with_default_log_config
            .is_authorized(&request, &entities)
            .await
            .unwrap()
            .decision(),
        Decision::Allow
    );
    assert_eq!(
        authorizer_with_all_fields_to_be_logged
            .is_authorized(&request, &entities)
            .await
            .unwrap()
            .decision(),
        Decision::Allow
    );
    assert_eq!(
        authorizer_with_no_field_from_entities_to_be_logged
            .is_authorized(&request, &entities)
            .await
            .unwrap()
            .decision(),
        Decision::Allow
    );
}

// Generated authorization logs are located at authorization_config.log
// For more information on tracing and its structured logging and diagnostics, visit:
// https://docs.rs/tracing/latest/tracing/
