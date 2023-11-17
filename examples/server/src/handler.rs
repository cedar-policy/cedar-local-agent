use hyper::http::Error;
use hyper::{Body, Request, Response};

pub async fn handler(_: Request<Body>) -> Result<Response<Body>, Error> {
    Ok(Response::new("Healthy".into()))
}
