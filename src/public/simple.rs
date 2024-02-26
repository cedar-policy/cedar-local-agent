//! Provides a simple authorizer that takes a `SimplePolicySetProvider` and a `SimpleEntityProvider`.
use std::sync::Arc;

use cedar_policy::{Entities, Request, Response};
#[cfg(feature = "partial-eval")]
use cedar_policy::{
    PartialResponse, PartialResponse::Concrete, PartialResponse::Residual, ResidualResponse,
};
use derive_builder::Builder;
use thiserror::Error;
use tokio::join;
use tracing::{debug, error, event, info, instrument};
use tracing_core::Level;
use uuid::Uuid;

use crate::public::log::schema::OpenCyberSecurityFramework;
use crate::public::{log, EntityProviderError, SimpleEntityProvider};
use crate::public::{PolicySetProviderError, SimplePolicySetProvider};

/// The `AuthorizerConfig` provides customers the ability to build their own
/// simple authorizer.
#[derive(Default, Builder, Debug)]
#[builder(pattern = "owned")]
pub struct AuthorizerConfig<P, E> {
    /// An atomic reference counter to a policy set provider
    pub policy_set_provider: Arc<P>,
    /// An atomic reference counter to an entity provider
    pub entity_provider: Arc<E>,
    /// An optional Logging Configuration
    #[builder(setter(into, strip_option), default)]
    pub log_config: Option<log::Config>,
}

/// `AuthorizerError` can be thrown when a provider fails to gather data.
#[derive(Error, Debug)]
pub enum AuthorizerError {
    /// Thrown when the `SimplePolicySetProvider` fails to get a `PolicySet`.
    #[error("The Policy Set Provider failed to get a policy set: {0}")]
    PolicySetProviderError(#[source] PolicySetProviderError),
    /// Thrown when the `SimpleEntityProvider` fails to get `Entities`.
    #[error("The Entity provider failed to get the entities: {0}")]
    EntityProviderError(#[source] EntityProviderError),
    /// Handles catching generic errors within the `Authorizer`.
    #[error("General error that can occur within the Authorizer: {0}")]
    General(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl From<PolicySetProviderError> for AuthorizerError {
    fn from(value: PolicySetProviderError) -> Self {
        Self::PolicySetProviderError(value)
    }
}

impl From<EntityProviderError> for AuthorizerError {
    fn from(value: EntityProviderError) -> Self {
        Self::EntityProviderError(value)
    }
}

/// `Authorizer` that provides an `is_authorized` implementation
#[derive(Debug)]
pub struct Authorizer<P, E>
where
    P: SimplePolicySetProvider + 'static,
    E: SimpleEntityProvider + 'static,
{
    /// the policy set provider -- provides the policies from a source location
    policy_set_provider: Arc<P>,
    /// the entity provider -- provides entities from on disk, a database look up etc.
    entity_provider: Arc<E>,
    /// Log config
    log_config: log::Config,
}

impl<P, E> Authorizer<P, E>
where
    P: SimplePolicySetProvider,
    E: SimpleEntityProvider,
{
    /// Constructor to create a `simple::Authorizer`
    ///
    /// # Examples:
    ///
    /// ```
    /// use std::sync::Arc;
    /// use cedar_local_agent::public::file::entity_provider::EntityProvider;
    /// use cedar_local_agent::public::file::policy_set_provider::{ConfigBuilder, PolicySetProvider};
    /// use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};
    ///
    /// let authorizer: Authorizer<PolicySetProvider, EntityProvider> = Authorizer::new(AuthorizerConfigBuilder::default()
    ///     .policy_set_provider(Arc::new(PolicySetProvider::new(
    ///             ConfigBuilder::default()
    ///                 .policy_set_path("tests/data/sweets.cedar")
    ///                 .build()
    ///                 .unwrap())
    ///         .unwrap()))
    ///     .entity_provider(Arc::new(EntityProvider::default()))
    ///     .build()
    ///     .unwrap());
    /// ```
    #[instrument(skip(configuration))]
    pub fn new(configuration: AuthorizerConfig<P, E>) -> Self {
        let log_config = configuration.log_config.unwrap_or_default();
        let entity_provider = configuration.entity_provider;
        info!("Initialized Entity Provider");
        let policy_set_provider = configuration.policy_set_provider;
        info!("Initialized Policy Set Provider");
        info!(
            "Initialize Simple Authorizer: authorizer_id= {:?}",
            log_config.requester
        );
        Self {
            policy_set_provider,
            entity_provider,
            log_config,
        }
    }

    /// Authorize
    ///
    /// # Errors
    ///
    /// This function can error if either the entity or policy set providers fails.
    #[instrument(fields(request_id = %Uuid::new_v4(), authorizer_id = %self.log_config.requester), skip_all, err(Debug))]
    pub async fn is_authorized(
        &self,
        request: &Request,
        entities: &Entities,
    ) -> Result<Response, AuthorizerError> {
        info!("Received request, running is_authorized...");

        let entities_future = self.entity_provider.get_entities(request);
        let policy_set_future = self.policy_set_provider.get_policy_set(request);
        let (fetched_entities, policy_set) = join!(entities_future, policy_set_future);
        let merged_entities = Entities::from_entities(
            fetched_entities?
                .as_ref()
                .iter()
                .chain(entities.iter())
                .cloned(),
            None,
        )
        .map_err(|e| AuthorizerError::General(Box::new(e)))?;

        let response = cedar_policy::Authorizer::new().is_authorized(
            request,
            policy_set?.as_ref(),
            &merged_entities,
        );
        info!("Fetched Authorization data from Policy Set Provider and Entity Provider");

        info!("Generated OCSF log record.");
        self.log(request, &response, entities);

        info!(
            "Is_authorized completed: response_decision={:?}",
            response.decision()
        );
        debug!(
            "This decision was reached because: response_diagnostics={:?}",
            response.diagnostics()
        );

        Ok(response)
    }

    #[instrument(skip_all)]
    fn log(&self, request: &Request, response: &Response, entities: &Entities) {
        event!(target: "cedar::simple::authorizer", Level::INFO, "{}",
            serde_json::to_string(
                &OpenCyberSecurityFramework::create(
                    request,
                    response,
                    entities,
                    &self.log_config.field_set,
                    self.log_config.requester.as_str(),
                )
                .unwrap_or_else(|e| {
                    OpenCyberSecurityFramework::error(e.to_string(), self.log_config.requester.clone())
                })
            ).unwrap_or_else(|_| "Failed to deserialize a known Open Cyber Security Framework string.".to_string()),
        );
    }

    /// Authorize Partial
    ///
    /// # Errors
    ///
    /// This function can error if either the entity or policy set providers fails.
    #[cfg(feature = "partial-eval")]
    #[instrument(fields(request_id = %Uuid::new_v4(), authorizer_id = %self.log_config.requester), skip_all, err(Debug))]
    pub async fn is_authorized_partial(
        &self,
        request: &Request,
        entities: &Entities,
    ) -> Result<PartialResponse, AuthorizerError> {
        info!("Received request, running is_authorized_partial...");

        let entities_future = self.entity_provider.get_entities(request);
        let policy_set_future = self.policy_set_provider.get_policy_set(request);
        let (fetched_entities, policy_set) = join!(entities_future, policy_set_future);
        let merged_entities = Entities::from_entities(
            fetched_entities?
                .as_ref()
                .iter()
                .chain(entities.iter())
                .cloned(),
            None,
        )
        .map_err(|e| AuthorizerError::General(Box::new(e)))?;

        let partial_response = cedar_policy::Authorizer::new().is_authorized_partial(
            request,
            policy_set?.as_ref(),
            &merged_entities.partial(),
        );
        info!("Fetched Authorization data from Policy Set Provider and Entity Provider");

        // Skip logging for now
        info!("Generated OCSF log record.");
        match &partial_response {
            Concrete(response) => self.log(request, response, entities),
            Residual(residual_response) => self.log_residual(request, residual_response, entities),
        };

        info!(
            "Is_authorized_partial completed: response_decision={}",
            match &partial_response {
                Concrete(response) => format!("{:?}", response.decision()),
                Residual(residual_response) => format!("{:?}", residual_response.residuals()),
            }
        );
        debug!(
            "This decision was reached because: response_diagnostics={:?}",
            match &partial_response {
                Concrete(response) => response.diagnostics(),
                Residual(residual_response) => residual_response.diagnostics(),
            }
        );

        Ok(partial_response)
    }

    #[cfg(feature = "partial-eval")]
    #[instrument(skip_all)]
    fn log_residual(
        &self,
        request: &Request,
        residual_response: &ResidualResponse,
        entities: &Entities,
    ) {
        event!(target: "cedar::simple::authorizer", Level::INFO, "{}",
            serde_json::to_string(
                &OpenCyberSecurityFramework::create_generic(
                    request,
                    residual_response.diagnostics(),
                    residual_response.residuals().policies()
                        .map(|policy| format!("{}", policy.id()))
                        .collect::<Vec<String>>()
                        .join(", ")
                        .as_str(),
                    String::from("Residuals"),
                    entities,
                    &self.log_config.field_set,
                    self.log_config.requester.as_str()
                ).unwrap_or_else(|e| {
                    OpenCyberSecurityFramework::error(e.to_string(), self.log_config.requester.clone())
                })
            ).unwrap_or_else(|_| "Failed to deserialize a known Open Cyber Security Framework string.".to_string()),
        );
    }
}

#[cfg(test)]
mod test {
    use std::fmt::Error;
    use std::sync::Arc;

    use async_trait::async_trait;
    use cedar_policy::{Context, Entities, PolicySet, Request};
    use cedar_policy_core::authorizer::Decision;

    use crate::public::log::DEFAULT_REQUESTER_NAME;
    use crate::public::simple::{Authorizer, AuthorizerConfigBuilder};
    use crate::public::{
        EntityProviderError, PolicySetProviderError, SimpleEntityProvider, SimplePolicySetProvider,
    };

    #[derive(Debug, Default)]
    pub struct MockPolicySetProvider;

    #[async_trait]
    impl SimplePolicySetProvider for MockPolicySetProvider {
        async fn get_policy_set(
            &self,
            _: &Request,
        ) -> Result<Arc<PolicySet>, PolicySetProviderError> {
            Ok(Arc::new(PolicySet::new()))
        }
    }

    #[derive(Debug, Default)]
    pub struct MockEntityProvider;

    #[async_trait]
    impl SimpleEntityProvider for MockEntityProvider {
        async fn get_entities(&self, _: &Request) -> Result<Arc<Entities>, EntityProviderError> {
            Ok(Arc::new(Entities::empty()))
        }
    }

    #[tokio::test]
    async fn simple_authorizer_is_ok() {
        let authorizer: Authorizer<MockPolicySetProvider, MockEntityProvider> = Authorizer::new(
            AuthorizerConfigBuilder::default()
                .policy_set_provider(Arc::new(MockPolicySetProvider))
                .entity_provider(Arc::new(MockEntityProvider))
                .build()
                .unwrap(),
        );

        let result = authorizer
            .is_authorized(
                &Request::new(
                    Some(r#"User::"Mike""#.parse().unwrap()),
                    Some(r#"Action::"View""#.parse().unwrap()),
                    Some(r#"Box::"10""#.parse().unwrap()),
                    Context::empty(),
                    None,
                )
                .unwrap(),
                &Entities::empty(),
            )
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().decision(), Decision::Deny);
        assert_eq!(authorizer.log_config.requester, DEFAULT_REQUESTER_NAME);
        assert!(!authorizer.log_config.field_set.principal);
    }

    #[derive(Debug, Default)]
    pub struct MockEntityProviderError;

    #[async_trait]
    impl SimpleEntityProvider for MockEntityProviderError {
        async fn get_entities(&self, _: &Request) -> Result<Arc<Entities>, EntityProviderError> {
            Err(EntityProviderError::General(Box::<Error>::default()))
        }
    }

    #[tokio::test]
    async fn simple_authorizer_bad_entity_provider() {
        let authorizer: Authorizer<MockPolicySetProvider, MockEntityProviderError> =
            Authorizer::new(
                AuthorizerConfigBuilder::default()
                    .policy_set_provider(Arc::new(MockPolicySetProvider))
                    .entity_provider(Arc::new(MockEntityProviderError))
                    .build()
                    .unwrap(),
            );

        let result = authorizer
            .is_authorized(
                &Request::new(
                    Some(r#"User::"Mike""#.parse().unwrap()),
                    Some(r#"Action::"View""#.parse().unwrap()),
                    Some(r#"Box::"2""#.parse().unwrap()),
                    Context::empty(),
                    None,
                )
                .unwrap(),
                &Entities::empty(),
            )
            .await;

        assert!(result.is_err());
    }

    #[derive(Debug, Default)]
    pub struct MockPolicySetProviderError;

    #[async_trait]
    impl SimplePolicySetProvider for MockPolicySetProviderError {
        async fn get_policy_set(
            &self,
            _: &Request,
        ) -> Result<Arc<PolicySet>, PolicySetProviderError> {
            Err(PolicySetProviderError::General(Box::<Error>::default()))
        }
    }

    #[tokio::test]
    async fn simple_authorizer_bad_policy_set_provider() {
        let authorizer: Authorizer<MockPolicySetProviderError, MockEntityProvider> =
            Authorizer::new(
                AuthorizerConfigBuilder::default()
                    .policy_set_provider(Arc::new(MockPolicySetProviderError))
                    .entity_provider(Arc::new(MockEntityProvider))
                    .build()
                    .unwrap(),
            );

        let result = authorizer
            .is_authorized(
                &Request::new(
                    Some(r#"User::"Mike""#.parse().unwrap()),
                    Some(r#"Action::"View""#.parse().unwrap()),
                    Some(r#"Box::"3""#.parse().unwrap()),
                    Context::empty(),
                    None,
                )
                .unwrap(),
                &Entities::empty(),
            )
            .await;

        assert!(result.is_err());
    }
}

#[cfg(test)]
#[cfg(feature = "partial-eval")]
mod test_partial {
    use std::sync::Arc;

    use async_trait::async_trait;
    use cedar_policy::{Context, Entities, PartialResponse, Policy, PolicySet, Request};
    use cedar_policy_core::authorizer::Decision;
    use cool_asserts::assert_matches;

    use crate::public::log::DEFAULT_REQUESTER_NAME;
    use crate::public::simple::test::{MockEntityProvider, MockPolicySetProvider};
    use crate::public::simple::{Authorizer, AuthorizerConfigBuilder};
    use crate::public::{PolicySetProviderError, SimplePolicySetProvider};

    #[tokio::test]
    async fn simple_authorizer_partial_no_resource_is_ok() {
        let authorizer: Authorizer<MockPolicySetProvider, MockEntityProvider> = Authorizer::new(
            AuthorizerConfigBuilder::default()
                .policy_set_provider(Arc::new(MockPolicySetProvider))
                .entity_provider(Arc::new(MockEntityProvider))
                .build()
                .unwrap(),
        );

        let result = authorizer
            .is_authorized_partial(
                &Request::builder()
                    .principal(Some(r#"User::"Mike""#.parse().unwrap()))
                    .action(Some(r#"Action::"View""#.parse().unwrap()))
                    .context(Context::empty())
                    .build()
                    .unwrap(),
                &Entities::empty(),
            )
            .await;

        assert_matches!(result, Ok(partial_response) =>
            assert_matches!(partial_response, PartialResponse::Concrete(response) =>
                assert_eq!(response.decision(), Decision::Deny)
            )
        );
        assert_eq!(authorizer.log_config.requester, DEFAULT_REQUESTER_NAME);
        assert!(!authorizer.log_config.field_set.principal);
    }

    #[tokio::test]
    async fn simple_authorizer_partial_no_principal_is_ok() {
        let authorizer: Authorizer<MockPolicySetProvider, MockEntityProvider> = Authorizer::new(
            AuthorizerConfigBuilder::default()
                .policy_set_provider(Arc::new(MockPolicySetProvider))
                .entity_provider(Arc::new(MockEntityProvider))
                .build()
                .unwrap(),
        );

        let result = authorizer
            .is_authorized_partial(
                &Request::builder()
                    .action(Some(r#"Action::"View""#.parse().unwrap()))
                    .resource(Some(r#"Box::"10""#.parse().unwrap()))
                    .context(Context::empty())
                    .build()
                    .unwrap(),
                &Entities::empty(),
            )
            .await;

        assert_matches!(result, Ok(partial_response) =>
            assert_matches!(partial_response, PartialResponse::Concrete(response) =>
                assert_eq!(response.decision(), Decision::Deny)
            )
        );
        assert_eq!(authorizer.log_config.requester, DEFAULT_REQUESTER_NAME);
        assert!(!authorizer.log_config.field_set.principal);
    }

    #[derive(Debug, Default)]
    pub struct MockPolicySetProviderPartial;

    #[async_trait]
    impl SimplePolicySetProvider for MockPolicySetProviderPartial {
        async fn get_policy_set(
            &self,
            _: &Request,
        ) -> Result<Arc<PolicySet>, PolicySetProviderError> {
            let policy = Policy::parse(
                Some("test".into()),
                r#"permit(principal == User::"Mike", action, resource == Box::"10");"#,
            )
            .expect("Failed to parse");
            let mut policy_set = PolicySet::new();
            policy_set.add(policy).expect("Failed to add");
            Ok(Arc::new(policy_set))
        }
    }

    #[tokio::test]
    async fn simple_authorizer_partial_result() {
        let authorizer: Authorizer<MockPolicySetProviderPartial, MockEntityProvider> =
            Authorizer::new(
                AuthorizerConfigBuilder::default()
                    .policy_set_provider(Arc::new(MockPolicySetProviderPartial))
                    .entity_provider(Arc::new(MockEntityProvider))
                    .build()
                    .unwrap(),
            );

        let result = authorizer
            .is_authorized_partial(
                &Request::builder()
                    .action(Some(r#"Action::"View""#.parse().unwrap()))
                    .resource(Some(r#"Box::"10""#.parse().unwrap()))
                    .context(Context::empty())
                    .build()
                    .unwrap(),
                &Entities::empty(),
            )
            .await;

        assert_matches!(result, Ok(partial_response) =>
            assert_matches!(partial_response, PartialResponse::Residual(residual_response) => {
                assert_eq!(residual_response.residuals().policies().count(), 1);
            })
        );
        assert_eq!(authorizer.log_config.requester, DEFAULT_REQUESTER_NAME);
        assert!(!authorizer.log_config.field_set.principal);
    }
}
