#[cfg(test)]
mod test {
    use std::fs;
    use std::fs::File;
    use std::path::Path;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    use cedar_policy::{Context, Entities, PolicySet, Request, Schema};
    use cedar_policy_core::authorizer::Decision;
    use tempfile::NamedTempFile;

    use cedar_local_agent::public::events::core::{file_inspector_task, RefreshRate};
    use cedar_local_agent::public::events::receive::update_provider_data_task;
    use cedar_local_agent::public::file::entity_provider::EntityProvider;
    use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
    use cedar_local_agent::public::file::{entity_provider, policy_set_provider};
    use cedar_local_agent::public::log;
    use cedar_local_agent::public::log::{FieldLevel, FieldSetBuilder, Format};
    use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};

    fn build_request(principal: &str, action: &str, resource: i32) -> Request {
        Request::new(
            format!("User::\"{principal}\"").parse().unwrap(),
            format!("Action::\"{action}\"").parse().unwrap(),
            format!("Box::\"{resource}\"").parse().unwrap(),
            Context::empty(),
            None,
        )
        .unwrap()
    }

    fn requests_with_missing_entities() -> Vec<(Request, Decision)> {
        Vec::from([
            (build_request("Mike", "read", 1), Decision::Deny),
            (build_request("Mike", "read", 2), Decision::Allow),
            (build_request("Mike", "read", 3), Decision::Deny),
            (build_request("Mike", "read", 4), Decision::Deny),
            (build_request("Mike", "read", 5), Decision::Deny),
            (build_request("Mike", "read", 7), Decision::Deny),
            (build_request("Mike", "read", 8), Decision::Deny),
            (build_request("Mike", "read", 9), Decision::Deny),
            (build_request("Mike", "read", 10), Decision::Deny),
            (build_request("Mike", "update", 1), Decision::Allow),
            (build_request("Mike", "update", 2), Decision::Deny),
            (build_request("Mike", "update", 3), Decision::Deny),
            (build_request("Mike", "update", 4), Decision::Deny),
            (build_request("Mike", "update", 5), Decision::Deny),
            (build_request("Mike", "update", 6), Decision::Deny),
            (build_request("Mike", "update", 7), Decision::Deny),
            (build_request("Mike", "update", 8), Decision::Deny),
            (build_request("Mike", "update", 9), Decision::Deny),
            (build_request("Mike", "update", 10), Decision::Deny),
            (build_request("Mike", "delete", 1), Decision::Deny),
            (build_request("Mike", "delete", 2), Decision::Deny),
            (build_request("Mike", "delete", 3), Decision::Deny),
            (build_request("Mike", "delete", 4), Decision::Deny),
            (build_request("Mike", "delete", 5), Decision::Deny),
            (build_request("Mike", "delete", 6), Decision::Deny),
            (build_request("Mike", "delete", 7), Decision::Deny),
            (build_request("Mike", "delete", 8), Decision::Deny),
            (build_request("Mike", "delete", 9), Decision::Deny),
            (build_request("Mike", "delete", 10), Decision::Deny),
            (build_request("Eric", "read", 1), Decision::Deny),
            (build_request("Eric", "read", 2), Decision::Deny),
            (build_request("Eric", "read", 3), Decision::Deny),
            (build_request("Eric", "read", 4), Decision::Deny),
            (build_request("Eric", "read", 5), Decision::Deny),
            (build_request("Eric", "read", 7), Decision::Deny),
            (build_request("Eric", "read", 8), Decision::Deny),
            (build_request("Eric", "read", 9), Decision::Allow),
            (build_request("Eric", "read", 10), Decision::Deny),
            (build_request("Eric", "update", 1), Decision::Deny),
            (build_request("Eric", "update", 2), Decision::Deny),
            (build_request("Eric", "update", 3), Decision::Deny),
            (build_request("Eric", "update", 4), Decision::Deny),
            (build_request("Eric", "update", 5), Decision::Deny),
            (build_request("Eric", "update", 6), Decision::Deny),
            (build_request("Eric", "update", 7), Decision::Deny),
            (build_request("Eric", "update", 8), Decision::Deny),
            (build_request("Eric", "update", 9), Decision::Deny),
            (build_request("Eric", "update", 10), Decision::Allow),
            (build_request("Eric", "delete", 1), Decision::Deny),
            (build_request("Eric", "delete", 2), Decision::Deny),
            (build_request("Eric", "delete", 3), Decision::Deny),
            (build_request("Eric", "delete", 4), Decision::Deny),
            (build_request("Eric", "delete", 5), Decision::Deny),
            (build_request("Eric", "delete", 6), Decision::Deny),
            (build_request("Eric", "delete", 7), Decision::Deny),
            (build_request("Eric", "delete", 8), Decision::Deny),
            (build_request("Eric", "delete", 9), Decision::Deny),
            (build_request("Eric", "delete", 10), Decision::Deny),
        ])
    }

    fn requests() -> Vec<(Request, Decision)> {
        Vec::from([
            (build_request("Mike", "read", 1), Decision::Deny),
            (build_request("Mike", "read", 2), Decision::Allow),
            (build_request("Mike", "read", 3), Decision::Deny),
            (build_request("Mike", "read", 4), Decision::Deny),
            (build_request("Mike", "read", 5), Decision::Deny),
            (build_request("Mike", "read", 7), Decision::Allow),
            (build_request("Mike", "read", 8), Decision::Allow),
            (build_request("Mike", "read", 9), Decision::Allow),
            (build_request("Mike", "read", 10), Decision::Allow),
            (build_request("Mike", "update", 1), Decision::Allow),
            (build_request("Mike", "update", 2), Decision::Deny),
            (build_request("Mike", "update", 3), Decision::Deny),
            (build_request("Mike", "update", 4), Decision::Deny),
            (build_request("Mike", "update", 5), Decision::Deny),
            (build_request("Mike", "update", 6), Decision::Allow),
            (build_request("Mike", "update", 7), Decision::Allow),
            (build_request("Mike", "update", 8), Decision::Allow),
            (build_request("Mike", "update", 9), Decision::Allow),
            (build_request("Mike", "update", 10), Decision::Allow),
            (build_request("Mike", "delete", 1), Decision::Deny),
            (build_request("Mike", "delete", 2), Decision::Deny),
            (build_request("Mike", "delete", 3), Decision::Deny),
            (build_request("Mike", "delete", 4), Decision::Deny),
            (build_request("Mike", "delete", 5), Decision::Deny),
            (build_request("Mike", "delete", 6), Decision::Allow),
            (build_request("Mike", "delete", 7), Decision::Allow),
            (build_request("Mike", "delete", 8), Decision::Allow),
            (build_request("Mike", "delete", 9), Decision::Allow),
            (build_request("Mike", "delete", 10), Decision::Allow),
            (build_request("Eric", "read", 1), Decision::Allow),
            (build_request("Eric", "read", 2), Decision::Allow),
            (build_request("Eric", "read", 3), Decision::Allow),
            (build_request("Eric", "read", 4), Decision::Allow),
            (build_request("Eric", "read", 5), Decision::Allow),
            (build_request("Eric", "read", 7), Decision::Deny),
            (build_request("Eric", "read", 8), Decision::Deny),
            (build_request("Eric", "read", 9), Decision::Allow),
            (build_request("Eric", "read", 10), Decision::Deny),
            (build_request("Eric", "update", 1), Decision::Allow),
            (build_request("Eric", "update", 2), Decision::Allow),
            (build_request("Eric", "update", 3), Decision::Allow),
            (build_request("Eric", "update", 4), Decision::Allow),
            (build_request("Eric", "update", 5), Decision::Allow),
            (build_request("Eric", "update", 6), Decision::Deny),
            (build_request("Eric", "update", 7), Decision::Deny),
            (build_request("Eric", "update", 8), Decision::Deny),
            (build_request("Eric", "update", 9), Decision::Deny),
            (build_request("Eric", "update", 10), Decision::Allow),
            (build_request("Eric", "delete", 1), Decision::Allow),
            (build_request("Eric", "delete", 2), Decision::Allow),
            (build_request("Eric", "delete", 3), Decision::Allow),
            (build_request("Eric", "delete", 4), Decision::Allow),
            (build_request("Eric", "delete", 5), Decision::Allow),
            (build_request("Eric", "delete", 6), Decision::Deny),
            (build_request("Eric", "delete", 7), Decision::Deny),
            (build_request("Eric", "delete", 8), Decision::Deny),
            (build_request("Eric", "delete", 9), Decision::Deny),
            (build_request("Eric", "delete", 10), Decision::Deny),
        ])
    }

    fn requests_with_differing_input_entities() -> Vec<(Request, Decision)> {
        Vec::from([
            (build_request("Mike", "read", 1), Decision::Allow),
            (build_request("Mike", "read", 2), Decision::Allow),
            (build_request("Mike", "read", 3), Decision::Allow),
            (build_request("Mike", "read", 4), Decision::Allow),
            (build_request("Mike", "read", 5), Decision::Allow),
            (build_request("Mike", "read", 7), Decision::Deny),
            (build_request("Mike", "read", 8), Decision::Deny),
            (build_request("Mike", "read", 9), Decision::Deny),
            (build_request("Mike", "read", 10), Decision::Deny),
            (build_request("Mike", "update", 1), Decision::Allow),
            (build_request("Mike", "update", 2), Decision::Allow),
            (build_request("Mike", "update", 3), Decision::Allow),
            (build_request("Mike", "update", 4), Decision::Allow),
            (build_request("Mike", "update", 5), Decision::Allow),
            (build_request("Mike", "update", 6), Decision::Deny),
            (build_request("Mike", "update", 7), Decision::Deny),
            (build_request("Mike", "update", 8), Decision::Deny),
            (build_request("Mike", "update", 9), Decision::Deny),
            (build_request("Mike", "update", 10), Decision::Deny),
            (build_request("Mike", "delete", 1), Decision::Allow),
            (build_request("Mike", "delete", 2), Decision::Allow),
            (build_request("Mike", "delete", 3), Decision::Allow),
            (build_request("Mike", "delete", 4), Decision::Allow),
            (build_request("Mike", "delete", 5), Decision::Allow),
            (build_request("Mike", "delete", 6), Decision::Deny),
            (build_request("Mike", "delete", 7), Decision::Deny),
            (build_request("Mike", "delete", 8), Decision::Deny),
            (build_request("Mike", "delete", 9), Decision::Deny),
            (build_request("Mike", "delete", 10), Decision::Deny),
            (build_request("Eric", "read", 1), Decision::Deny),
            (build_request("Eric", "read", 2), Decision::Deny),
            (build_request("Eric", "read", 3), Decision::Deny),
            (build_request("Eric", "read", 4), Decision::Deny),
            (build_request("Eric", "read", 5), Decision::Deny),
            (build_request("Eric", "read", 6), Decision::Allow),
            (build_request("Eric", "read", 7), Decision::Allow),
            (build_request("Eric", "read", 8), Decision::Allow),
            (build_request("Eric", "read", 9), Decision::Allow),
            (build_request("Eric", "read", 10), Decision::Allow),
            (build_request("Eric", "update", 1), Decision::Deny),
            (build_request("Eric", "update", 2), Decision::Deny),
            (build_request("Eric", "update", 3), Decision::Deny),
            (build_request("Eric", "update", 4), Decision::Deny),
            (build_request("Eric", "update", 5), Decision::Deny),
            (build_request("Eric", "update", 6), Decision::Allow),
            (build_request("Eric", "update", 7), Decision::Allow),
            (build_request("Eric", "update", 8), Decision::Allow),
            (build_request("Eric", "update", 9), Decision::Allow),
            (build_request("Eric", "update", 10), Decision::Allow),
            (build_request("Eric", "delete", 1), Decision::Deny),
            (build_request("Eric", "delete", 2), Decision::Deny),
            (build_request("Eric", "delete", 3), Decision::Deny),
            (build_request("Eric", "delete", 4), Decision::Deny),
            (build_request("Eric", "delete", 5), Decision::Deny),
            (build_request("Eric", "delete", 6), Decision::Allow),
            (build_request("Eric", "delete", 7), Decision::Allow),
            (build_request("Eric", "delete", 8), Decision::Allow),
            (build_request("Eric", "delete", 9), Decision::Allow),
            (build_request("Eric", "delete", 10), Decision::Allow),
        ])
    }

    fn requests_with_group() -> Vec<(Request, Decision)> {
        Vec::from([
            (build_request("Mike", "read", 1), Decision::Deny),
            (build_request("Mike", "read", 2), Decision::Allow),
            (build_request("Mike", "read", 3), Decision::Deny),
            (build_request("Mike", "read", 4), Decision::Deny),
            (build_request("Mike", "read", 5), Decision::Deny),
            (build_request("Mike", "read", 6), Decision::Allow),
            (build_request("Mike", "read", 7), Decision::Allow),
            (build_request("Mike", "read", 8), Decision::Allow),
            (build_request("Mike", "read", 9), Decision::Allow),
            (build_request("Mike", "read", 10), Decision::Allow),
            (build_request("Mike", "read", 11), Decision::Allow),
            (build_request("Mike", "read", 12), Decision::Allow),
            (build_request("Mike", "update", 1), Decision::Allow),
            (build_request("Mike", "update", 2), Decision::Deny),
            (build_request("Mike", "update", 3), Decision::Deny),
            (build_request("Mike", "update", 4), Decision::Deny),
            (build_request("Mike", "update", 5), Decision::Deny),
            (build_request("Mike", "update", 6), Decision::Allow),
            (build_request("Mike", "update", 7), Decision::Allow),
            (build_request("Mike", "update", 8), Decision::Allow),
            (build_request("Mike", "update", 9), Decision::Allow),
            (build_request("Mike", "update", 10), Decision::Allow),
            (build_request("Mike", "update", 11), Decision::Allow),
            (build_request("Mike", "update", 12), Decision::Allow),
            (build_request("Mike", "delete", 1), Decision::Deny),
            (build_request("Mike", "delete", 2), Decision::Deny),
            (build_request("Mike", "delete", 3), Decision::Deny),
            (build_request("Mike", "delete", 4), Decision::Deny),
            (build_request("Mike", "delete", 5), Decision::Deny),
            (build_request("Mike", "delete", 6), Decision::Allow),
            (build_request("Mike", "delete", 7), Decision::Allow),
            (build_request("Mike", "delete", 8), Decision::Allow),
            (build_request("Mike", "delete", 9), Decision::Allow),
            (build_request("Mike", "delete", 10), Decision::Allow),
            (build_request("Mike", "delete", 11), Decision::Allow),
            (build_request("Mike", "delete", 12), Decision::Allow),
            (build_request("Eric", "read", 1), Decision::Allow),
            (build_request("Eric", "read", 2), Decision::Allow),
            (build_request("Eric", "read", 3), Decision::Allow),
            (build_request("Eric", "read", 4), Decision::Allow),
            (build_request("Eric", "read", 5), Decision::Allow),
            (build_request("Eric", "read", 6), Decision::Deny),
            (build_request("Eric", "read", 7), Decision::Deny),
            (build_request("Eric", "read", 8), Decision::Deny),
            (build_request("Eric", "read", 9), Decision::Allow),
            (build_request("Eric", "read", 10), Decision::Deny),
            (build_request("Eric", "read", 11), Decision::Allow),
            (build_request("Eric", "read", 12), Decision::Deny),
            (build_request("Eric", "update", 1), Decision::Allow),
            (build_request("Eric", "update", 2), Decision::Allow),
            (build_request("Eric", "update", 3), Decision::Allow),
            (build_request("Eric", "update", 4), Decision::Allow),
            (build_request("Eric", "update", 5), Decision::Allow),
            (build_request("Eric", "update", 6), Decision::Deny),
            (build_request("Eric", "update", 7), Decision::Deny),
            (build_request("Eric", "update", 8), Decision::Deny),
            (build_request("Eric", "update", 9), Decision::Deny),
            (build_request("Eric", "update", 10), Decision::Allow),
            (build_request("Eric", "update", 11), Decision::Allow),
            (build_request("Eric", "update", 12), Decision::Deny),
            (build_request("Eric", "delete", 1), Decision::Allow),
            (build_request("Eric", "delete", 2), Decision::Allow),
            (build_request("Eric", "delete", 3), Decision::Allow),
            (build_request("Eric", "delete", 4), Decision::Allow),
            (build_request("Eric", "delete", 5), Decision::Allow),
            (build_request("Eric", "delete", 6), Decision::Deny),
            (build_request("Eric", "delete", 7), Decision::Deny),
            (build_request("Eric", "delete", 8), Decision::Deny),
            (build_request("Eric", "delete", 9), Decision::Deny),
            (build_request("Eric", "delete", 10), Decision::Deny),
            (build_request("Eric", "delete", 11), Decision::Deny),
            (build_request("Eric", "delete", 12), Decision::Deny),
            (build_request("Phil", "read", 1), Decision::Deny),
            (build_request("Phil", "read", 2), Decision::Deny),
            (build_request("Phil", "read", 3), Decision::Deny),
            (build_request("Phil", "read", 4), Decision::Deny),
            (build_request("Phil", "read", 5), Decision::Deny),
            (build_request("Phil", "read", 6), Decision::Deny),
            (build_request("Phil", "read", 7), Decision::Deny),
            (build_request("Phil", "read", 8), Decision::Deny),
            (build_request("Phil", "read", 9), Decision::Deny),
            (build_request("Phil", "read", 10), Decision::Deny),
            (build_request("Phil", "read", 11), Decision::Allow),
            (build_request("Phil", "read", 12), Decision::Allow),
            (build_request("Phil", "update", 1), Decision::Deny),
            (build_request("Phil", "update", 2), Decision::Deny),
            (build_request("Phil", "update", 3), Decision::Deny),
            (build_request("Phil", "update", 4), Decision::Deny),
            (build_request("Phil", "update", 5), Decision::Deny),
            (build_request("Phil", "update", 6), Decision::Deny),
            (build_request("Phil", "update", 7), Decision::Deny),
            (build_request("Phil", "update", 8), Decision::Deny),
            (build_request("Phil", "update", 9), Decision::Deny),
            (build_request("Phil", "update", 10), Decision::Deny),
            (build_request("Phil", "update", 11), Decision::Allow),
            (build_request("Phil", "update", 12), Decision::Allow),
            (build_request("Phil", "delete", 1), Decision::Deny),
            (build_request("Phil", "delete", 2), Decision::Deny),
            (build_request("Phil", "delete", 3), Decision::Deny),
            (build_request("Phil", "delete", 4), Decision::Deny),
            (build_request("Phil", "delete", 5), Decision::Deny),
            (build_request("Phil", "delete", 6), Decision::Deny),
            (build_request("Phil", "delete", 7), Decision::Deny),
            (build_request("Phil", "delete", 8), Decision::Deny),
            (build_request("Phil", "delete", 9), Decision::Deny),
            (build_request("Phil", "delete", 10), Decision::Deny),
            (build_request("Phil", "delete", 11), Decision::Deny),
            (build_request("Phil", "delete", 12), Decision::Deny),
            (build_request("Alice", "read", 1), Decision::Allow),
            (build_request("Alice", "read", 2), Decision::Allow),
            (build_request("Alice", "read", 3), Decision::Allow),
            (build_request("Alice", "read", 4), Decision::Allow),
            (build_request("Alice", "read", 5), Decision::Allow),
            (build_request("Alice", "read", 6), Decision::Allow),
            (build_request("Alice", "read", 7), Decision::Allow),
            (build_request("Alice", "read", 8), Decision::Allow),
            (build_request("Alice", "read", 9), Decision::Allow),
            (build_request("Alice", "read", 10), Decision::Allow),
            (build_request("Alice", "read", 11), Decision::Allow),
            (build_request("Alice", "read", 12), Decision::Allow),
            (build_request("Alice", "update", 1), Decision::Allow),
            (build_request("Alice", "update", 2), Decision::Allow),
            (build_request("Alice", "update", 3), Decision::Allow),
            (build_request("Alice", "update", 4), Decision::Allow),
            (build_request("Alice", "update", 5), Decision::Allow),
            (build_request("Alice", "update", 6), Decision::Allow),
            (build_request("Alice", "update", 7), Decision::Allow),
            (build_request("Alice", "update", 8), Decision::Allow),
            (build_request("Alice", "update", 9), Decision::Allow),
            (build_request("Alice", "update", 10), Decision::Allow),
            (build_request("Alice", "update", 11), Decision::Allow),
            (build_request("Alice", "update", 12), Decision::Allow),
            (build_request("Alice", "delete", 1), Decision::Allow),
            (build_request("Alice", "delete", 2), Decision::Allow),
            (build_request("Alice", "delete", 3), Decision::Allow),
            (build_request("Alice", "delete", 4), Decision::Allow),
            (build_request("Alice", "delete", 5), Decision::Allow),
            (build_request("Alice", "delete", 6), Decision::Allow),
            (build_request("Alice", "delete", 7), Decision::Allow),
            (build_request("Alice", "delete", 8), Decision::Allow),
            (build_request("Alice", "delete", 9), Decision::Allow),
            (build_request("Alice", "delete", 10), Decision::Allow),
            (build_request("Alice", "delete", 11), Decision::Allow),
            (build_request("Alice", "delete", 12), Decision::Allow),
        ])
    }

    #[tokio::test]
    async fn authorize_with_group_of_entities() {
        let policy_set_provider = Arc::new(
            PolicySetProvider::new(
                policy_set_provider::ConfigBuilder::default()
                    .policy_set_path("tests/data/sweets.cedar")
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );

        let entity_provider = Arc::new(
            EntityProvider::new(
                entity_provider::ConfigBuilder::default()
                    .entities_path("tests/data/sweets.entities.json")
                    .schema_path("tests/data/sweets.schema.cedar.json")
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );

        let authorizer: Authorizer<PolicySetProvider, EntityProvider> = Authorizer::new(
            AuthorizerConfigBuilder::default()
                .entity_provider(entity_provider)
                .policy_set_provider(policy_set_provider)
                .build()
                .unwrap(),
        );

        validate_requests(&authorizer, requests_with_group()).await;
    }

    #[tokio::test]
    #[should_panic]
    async fn authorize_with_duplicated_input_entities_should_panic() {
        let policy_set_provider = Arc::new(
            PolicySetProvider::new(
                policy_set_provider::ConfigBuilder::default()
                    .policy_set_path("tests/data/sweets.cedar")
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );

        let entity_provider = Arc::new(
            EntityProvider::new(
                entity_provider::ConfigBuilder::default()
                    .entities_path("tests/data/sweets.entities.json")
                    .schema_path("tests/data/sweets.schema.cedar.json")
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );

        let authorizer: Authorizer<PolicySetProvider, EntityProvider> = Authorizer::new(
            AuthorizerConfigBuilder::default()
                .entity_provider(entity_provider)
                .policy_set_provider(policy_set_provider)
                .build()
                .unwrap(),
        );

        let entities_file = File::open("tests/data/sweets_input.entities.json").unwrap();
        let schema_file = File::open("tests/data/sweets.schema.cedar.json").unwrap();
        let schema = Schema::from_json_file(schema_file).unwrap();
        let entities = Entities::from_json_file(entities_file, Some(&schema)).unwrap();
        // This panics now due to enhanced entity validation in cedar-policy 3.0.0
        validate_requests_with_entities(
            &authorizer,
            &entities,
            requests_with_differing_input_entities(),
        )
        .await;
    }

    #[tokio::test]
    async fn authorizer_with_sweets_app_no_updates() {
        let policy_set_provider = Arc::new(
            PolicySetProvider::new(
                policy_set_provider::ConfigBuilder::default()
                    .policy_set_path("tests/data/sweets.cedar")
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );

        let entity_provider = Arc::new(
            EntityProvider::new(
                entity_provider::ConfigBuilder::default()
                    .entities_path("tests/data/sweets.entities.json")
                    .schema_path("tests/data/sweets.schema.cedar.json")
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );

        let authorizer: Authorizer<PolicySetProvider, EntityProvider> = Authorizer::new(
            AuthorizerConfigBuilder::default()
                .entity_provider(entity_provider)
                .policy_set_provider(policy_set_provider)
                .log_config(
                    log::ConfigBuilder::default()
                        .format(Format::OpenCyberSecurityFramework)
                        .field_set(
                            FieldSetBuilder::default()
                                .resource(false)
                                .action(false)
                                .principal(false)
                                .entities(FieldLevel::None)
                                .context(false)
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        );

        validate_requests(&authorizer, requests()).await;
    }

    #[tokio::test]
    async fn authorizer_with_sweets_app_with_policy_set_update() {
        let temp_file = NamedTempFile::new().unwrap();
        let temp_file_path = temp_file.path().to_str().unwrap().to_string();

        let policy_set_provider = Arc::new(
            PolicySetProvider::new(
                policy_set_provider::ConfigBuilder::default()
                    .policy_set_path(temp_file_path.clone())
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );

        let (_, receiver) = file_inspector_task(
            RefreshRate::Other(Duration::from_millis(1)),
            temp_file_path.clone(),
        );
        let mut test_receiver = receiver.resubscribe();
        let _update_provider_thread =
            update_provider_data_task(policy_set_provider.clone(), receiver);

        let entity_provider = Arc::new(
            EntityProvider::new(
                entity_provider::ConfigBuilder::default()
                    .entities_path("tests/data/sweets.entities.json")
                    .schema_path("tests/data/sweets.schema.cedar.json")
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );

        let authorizer: Authorizer<PolicySetProvider, EntityProvider> = Authorizer::new(
            AuthorizerConfigBuilder::default()
                .entity_provider(entity_provider)
                .policy_set_provider(policy_set_provider)
                .build()
                .unwrap(),
        );

        // Blank file with no policies, all should be deny
        validate_requests_all_deny(&authorizer, requests()).await;

        assert!(test_receiver.recv().await.is_ok());
        assert!(fs::copy("tests/data/sweets.cedar", temp_file_path).is_ok());
        assert!(test_receiver.recv().await.is_ok());

        // File copied should match expected request decision criteria
        validate_requests(&authorizer, requests()).await;
    }

    #[tokio::test]
    async fn authorizer_with_sweets_app_with_policy_set_update_with_default_refresh_rate() {
        let temp_file = NamedTempFile::new().unwrap();
        let temp_file_path = temp_file.path().to_str().unwrap().to_string();

        let policy_set_provider = Arc::new(
            PolicySetProvider::new(
                policy_set_provider::ConfigBuilder::default()
                    .policy_set_path(temp_file_path.clone())
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );

        let (_, receiver) =
            file_inspector_task(RefreshRate::FifteenSeconds, temp_file_path.clone());
        let mut test_receiver = receiver.resubscribe();
        let _update_provider_thread =
            update_provider_data_task(policy_set_provider.clone(), receiver);

        let entity_provider = Arc::new(
            EntityProvider::new(
                entity_provider::ConfigBuilder::default()
                    .entities_path("tests/data/sweets.entities.json")
                    .schema_path("tests/data/sweets.schema.cedar.json")
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );

        let authorizer: Authorizer<PolicySetProvider, EntityProvider> = Authorizer::new(
            AuthorizerConfigBuilder::default()
                .entity_provider(entity_provider)
                .policy_set_provider(policy_set_provider)
                .build()
                .unwrap(),
        );

        // Blank file with no policies, all should be deny
        validate_requests_all_deny(&authorizer, requests()).await;

        assert!(test_receiver.recv().await.is_ok());
        assert!(fs::copy("tests/data/sweets.cedar", temp_file_path).is_ok());
        assert!(test_receiver.recv().await.is_ok());

        // File copied should match expected request decision criteria
        validate_requests(&authorizer, requests()).await;
    }

    #[tokio::test]
    async fn authorizer_with_sweets_app_with_policy_set_entities_updates() {
        let policy_set_temp_file = NamedTempFile::new().unwrap();
        let policy_set_temp_file_path = policy_set_temp_file.path().to_str().unwrap().to_string();
        let (_, policy_set_receiver) = file_inspector_task(
            RefreshRate::Other(Duration::from_millis(1)),
            policy_set_temp_file_path.clone(),
        );

        let entities_temp_file = NamedTempFile::new().unwrap();
        let entities_temp_file_path = entities_temp_file.path().to_str().unwrap().to_string();
        assert!(fs::write(entities_temp_file_path.clone(), "[]").is_ok());
        let (_, entities_receiver) = file_inspector_task(
            RefreshRate::Other(Duration::from_millis(1)),
            entities_temp_file_path.clone(),
        );

        let policy_set_provider = Arc::new(
            PolicySetProvider::new(
                policy_set_provider::ConfigBuilder::default()
                    .policy_set_path(policy_set_temp_file_path.clone())
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );

        let mut test_policy_set_receiver = policy_set_receiver.resubscribe();
        let _update_policy_set_task =
            update_provider_data_task(policy_set_provider.clone(), policy_set_receiver);

        let entity_provider = Arc::new(
            EntityProvider::new(
                entity_provider::ConfigBuilder::default()
                    .entities_path(entities_temp_file_path.clone())
                    .schema_path("tests/data/sweets.schema.cedar.json")
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );

        let mut test_entities_receiver = entities_receiver.resubscribe();
        let _update_entity_task =
            update_provider_data_task(entity_provider.clone(), entities_receiver);

        let authorizer: Authorizer<PolicySetProvider, EntityProvider> = Authorizer::new(
            AuthorizerConfigBuilder::default()
                .entity_provider(entity_provider)
                .policy_set_provider(policy_set_provider)
                .build()
                .unwrap(),
        );

        // Blank file(s) with no policies and entities, all should be deny
        validate_requests_all_deny(&authorizer, requests()).await;

        assert!(test_policy_set_receiver.recv().await.is_ok());
        assert!(fs::copy("tests/data/sweets.cedar", policy_set_temp_file_path.clone()).is_ok());
        let policy_set_src =
            fs::read_to_string(Path::new(policy_set_temp_file_path.as_str())).unwrap();
        assert!(PolicySet::from_str(&policy_set_src).is_ok());
        assert!(test_policy_set_receiver.recv().await.is_ok());

        // Policies but with no entities
        validate_requests(&authorizer, requests_with_missing_entities()).await;

        assert!(test_entities_receiver.recv().await.is_ok());
        assert!(fs::copy(
            "tests/data/sweets.entities.json",
            entities_temp_file_path.clone()
        )
        .is_ok());

        let entities_file = File::open(entities_temp_file_path).unwrap();
        let schema_file = File::open("tests/data/sweets.schema.cedar.json").unwrap();
        let schema = Schema::from_json_file(schema_file).unwrap();
        assert!(Entities::from_json_file(entities_file, Some(&schema)).is_ok());
        assert!(test_entities_receiver.recv().await.is_ok());

        // File copied should match expected request decision criteria
        validate_requests(&authorizer, requests()).await;
    }

    #[tokio::test]
    #[should_panic]
    async fn authorizer_with_sweets_app_with_panic_on_malformed_policies_file_preload() {
        Arc::new(
            PolicySetProvider::new(
                policy_set_provider::ConfigBuilder::default()
                    .policy_set_path("tests/data/malformed_policies.cedar")
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );
    }

    #[tokio::test]
    async fn authorizer_with_sweets_app_with_update_with_malformed_policies_file() {
        let policy_set_temp_file = NamedTempFile::new().unwrap();
        let policy_set_temp_file_path = policy_set_temp_file.path().to_str().unwrap().to_string();

        assert!(fs::copy("tests/data/sweets.cedar", policy_set_temp_file_path.clone()).is_ok());
        let policy_set_src =
            fs::read_to_string(Path::new(policy_set_temp_file_path.as_str())).unwrap();
        assert!(PolicySet::from_str(&policy_set_src).is_ok());

        let policy_set_provider = Arc::new(
            PolicySetProvider::new(
                policy_set_provider::ConfigBuilder::default()
                    .policy_set_path(policy_set_temp_file_path.clone())
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );

        let (_, policy_set_receiver) = file_inspector_task(
            RefreshRate::Other(Duration::from_millis(1)),
            policy_set_temp_file_path.clone(),
        );
        let mut test_policy_set_receiver = policy_set_receiver.resubscribe();
        let _update_policy_set_task =
            update_provider_data_task(policy_set_provider.clone(), policy_set_receiver);

        let entity_provider = Arc::new(
            EntityProvider::new(
                entity_provider::ConfigBuilder::default()
                    .entities_path("tests/data/sweets.entities.json")
                    .schema_path("tests/data/sweets.schema.cedar.json")
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );

        let authorizer: Authorizer<PolicySetProvider, EntityProvider> = Authorizer::new(
            AuthorizerConfigBuilder::default()
                .entity_provider(entity_provider)
                .policy_set_provider(policy_set_provider)
                .build()
                .unwrap(),
        );

        validate_requests(&authorizer, requests()).await;

        assert!(test_policy_set_receiver.recv().await.is_ok());
        assert!(fs::copy(
            "tests/data/malformed_policies.cedar",
            policy_set_temp_file_path.clone()
        )
        .is_ok());
        let policy_set_src =
            fs::read_to_string(Path::new(policy_set_temp_file_path.as_str())).unwrap();
        assert!(PolicySet::from_str(&policy_set_src).is_err());
        assert!(test_policy_set_receiver.recv().await.is_ok());

        validate_requests(&authorizer, requests()).await;
    }

    #[tokio::test]
    #[should_panic]
    async fn authorizer_with_sweets_app_with_panic_on_malformed_entities_file_preload() {
        Arc::new(
            EntityProvider::new(
                entity_provider::ConfigBuilder::default()
                    .entities_path("tests/data/malformed_entities.json")
                    .schema_path("tests/data/sweets.schema.cedar.json")
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );
    }

    #[tokio::test]
    async fn authorizer_with_sweets_app_with_update_with_malformed_entities_file() {
        let policy_set_provider = Arc::new(
            PolicySetProvider::new(
                policy_set_provider::ConfigBuilder::default()
                    .policy_set_path("tests/data/sweets.cedar")
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );

        let entities_temp_file = NamedTempFile::new().unwrap();
        let entities_temp_file_path = entities_temp_file.path().to_str().unwrap().to_string();

        assert!(fs::copy(
            "tests/data/sweets.entities.json",
            entities_temp_file_path.clone()
        )
        .is_ok());

        let entities_file = File::open(entities_temp_file_path.clone()).unwrap();
        let schema_file_path = "tests/data/sweets.schema.cedar.json";
        let schema_file = File::open(schema_file_path).unwrap();
        let schema = Schema::from_json_file(schema_file).unwrap();
        assert!(Entities::from_json_file(entities_file, Some(&schema)).is_ok());

        let entity_provider = Arc::new(
            EntityProvider::new(
                entity_provider::ConfigBuilder::default()
                    .entities_path(entities_temp_file_path.clone())
                    .schema_path(schema_file_path)
                    .build()
                    .unwrap(),
            )
            .unwrap(),
        );

        let (_, entities_receiver) = file_inspector_task(
            RefreshRate::Other(Duration::from_millis(1)),
            entities_temp_file_path.clone(),
        );
        let mut test_entities_receiver = entities_receiver.resubscribe();
        let _update_entity_task =
            update_provider_data_task(entity_provider.clone(), entities_receiver);

        let authorizer: Authorizer<PolicySetProvider, EntityProvider> = Authorizer::new(
            AuthorizerConfigBuilder::default()
                .entity_provider(entity_provider)
                .policy_set_provider(policy_set_provider)
                .build()
                .unwrap(),
        );

        validate_requests(&authorizer, requests()).await;

        assert!(test_entities_receiver.recv().await.is_ok());
        assert!(fs::copy(
            "tests/data/malformed_entities.json",
            entities_temp_file_path.clone()
        )
        .is_ok());
        let entities_file = File::open(entities_temp_file_path).unwrap();
        let schema_file = File::open(schema_file_path).unwrap();
        let schema = Schema::from_json_file(schema_file).unwrap();
        assert!(Entities::from_json_file(entities_file, Some(&schema)).is_err());
        assert!(test_entities_receiver.recv().await.is_ok());

        validate_requests(&authorizer, requests()).await;
    }

    async fn validate_requests(
        authorizer: &Authorizer<PolicySetProvider, EntityProvider>,
        evaluation: Vec<(Request, Decision)>,
    ) {
        for (request, decision) in evaluation {
            let response = authorizer
                .is_authorized(&request, &Entities::empty())
                .await
                .unwrap();
            assert_eq!(response.decision(), decision)
        }
    }

    async fn validate_requests_with_entities(
        authorizer: &Authorizer<PolicySetProvider, EntityProvider>,
        entities: &Entities,
        evaluation: Vec<(Request, Decision)>,
    ) {
        for (request, decision) in evaluation {
            let response = authorizer.is_authorized(&request, entities).await.unwrap();
            assert_eq!(response.decision(), decision)
        }
    }

    async fn validate_requests_all_deny(
        authorizer: &Authorizer<PolicySetProvider, EntityProvider>,
        evaluation: Vec<(Request, Decision)>,
    ) {
        for (request, _) in evaluation {
            let response = authorizer
                .is_authorized(&request, &Entities::empty())
                .await
                .unwrap();
            assert_eq!(response.decision(), Decision::Deny)
        }
    }
}
