use std::sync::Arc;

use futures::future::{BoxFuture, FutureExt};
use hyper::{Body, Request as HttpRequest, Response, StatusCode};
use base64::Engine;
use tower_http::auth::AsyncAuthorizeRequest;
use tracing::{error, info};

use cedar_local_agent::public::file::entity_provider::EntityProvider;
use cedar_local_agent::public::file::policy_set_provider::PolicySetProvider;
use cedar_local_agent::public::simple::Authorizer;

use cedar_policy::{Entities, Request};
use cedar_policy_core::authorizer::Decision;

use crate::cedar_query::CedarQuery;

#[derive(Clone)]
pub struct Authorization {
    authorizer: Arc<Authorizer<PolicySetProvider, EntityProvider>>,
}

impl Authorization {
    pub fn new(authorizer: Authorizer<PolicySetProvider, EntityProvider>) -> Self {
        Self {
            authorizer: Arc::new(authorizer),
        }
    }
}

impl<B> AsyncAuthorizeRequest<B> for Authorization
where
    B: Send + Sync + 'static,
{
    type RequestBody = B;
    type ResponseBody = Body;
    type Future = BoxFuture<'static, Result<HttpRequest<B>, Response<Self::ResponseBody>>>;

    fn authorize(&mut self, request: HttpRequest<B>) -> Self::Future {
        let unauthorized_response = Err(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::empty())
            .unwrap());

        let authorizer = self.authorizer.clone();
        async move {
            let headers = request.headers();

            if !headers.contains_key("Authorization") {
                error!("Authorization Header not supplied");
                return unauthorized_response;
            }

        let authorization_header = headers.get("Authorization").unwrap();
            let authorization_string = match authorization_header.to_str() {
                Ok(authorization_string) => {
                    match base64::engine::general_purpose::STANDARD.decode(authorization_string) {
                        Ok(decoded_string) => String::from_utf8(decoded_string).unwrap(),
                        Err(error) => {
                            error!("Failed to base64 decode the string: {authorization_string:?}, Error: {:?}", error);
                            return unauthorized_response;
                        }
                    }
                }
                Err(error) => {
                    error!("Failed to deserialize the string, Error: {:?}", error);
                    return unauthorized_response;
                }
            };
            let query: CedarQuery = match serde_json::from_str(&authorization_string) {
                Ok(query) => query,
                Err(error) => {
                    error!(
                        "Failed to parse the query:{authorization_string} from the body: {:?}",
                        error
                    );
                    return unauthorized_response;
                }
            };
            let cedar_request = Request::try_from(query).unwrap();

            info!("Authorizing valid request: {:?}", cedar_request);
            let response = match authorizer
                .is_authorized(&cedar_request, &Entities::empty())
                .await
            {
                Ok(response) => response,
                Err(errors) => {
                    error!("Failed to authorize request: {:?}", errors);
                    return unauthorized_response;
                }
            };

            match response.decision() {
                Decision::Allow => Ok(request),
                Decision::Deny => unauthorized_response,
            }
        }
        .boxed()
    }
}
