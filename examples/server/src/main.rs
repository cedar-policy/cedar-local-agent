use std::iter::once;
use std::net::SocketAddr;
use std::sync::Arc;

use hyper::header::AUTHORIZATION;
use hyper::Server;
use tower::make::Shared;
use tower::ServiceBuilder;
use tower_http::auth::AsyncRequireAuthorizationLayer;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
use cedar_local_agent::public::file::{entity_provider, policy_set_provider};
use cedar_local_agent::public::simple::{Authorizer, AuthorizerConfigBuilder};

mod authorization;
mod cedar_query;
mod handler;

use authorization::Authorization;
use handler::handler;

#[tokio::main]
pub async fn main() {
    /*
     * Build a local authorizer that evaluates authorization decisions using a locally stored policy set, entity store and schema.
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
     * Build a hyper service that handles incoming requests and delegates them to the local authorizer.
     */

    let service = ServiceBuilder::new()
        .layer(SetSensitiveRequestHeadersLayer::new(once(AUTHORIZATION)))
        .layer(TraceLayer::new_for_http())
        .layer(AsyncRequireAuthorizationLayer::new(Authorization::new(
            authorizer,
        )))
        .service_fn(handler);

    let address = SocketAddr::from(([127, 0, 0, 1], 3000));

    info!("Server starting on {:?}", address);

    Server::bind(&address)
        .serve(Shared::new(service))
        .await
        .expect("Server failed to start");
}
