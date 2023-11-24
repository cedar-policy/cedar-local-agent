//! Module contains a simple entity provider, and policy provider and authorizer.
use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use cedar_policy::{Entities, PolicySet, Request};
use thiserror::Error;

pub mod events;
pub mod file;
pub mod log;
pub mod simple;

// Note: These are initial settings. We may adjust these maximums as we learn more
const MAX_ENTITIES_COUNT: usize = 100;
/// Equal to 10KB (1KB = 1024 bytes)
const MAX_REQUEST_SIZE_BYTES: usize = 10_240;
/// Equal to 100KB (1KB = 1024 bytes)
const MAX_ENTITIES_SIZE_BYTES: usize = 102_400;

/// `EntityProviderError` is a general error that any implementation of trait
/// `SimpleEntityProvider` can return as an error.
#[derive(Error, Debug)]
pub enum EntityProviderError {
    /// `General` error case, designed to be used with any source std error.
    #[error("Entity Provider failed to get the entities: {0}")]
    General(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// `SimpleEntitySetProvider` trait provides a simple trait for gathering entities.  Some use cases
/// include getting data from a simple file system location or a database call.
///
/// The cedar `Request` is passed to the provider as it contains information on the `Principal` trying to
/// perform some `Action` on a `Resource` within some `Context`.  The `Principal` and `Resource` information
/// can help inform the implementer of what resources to gather from various `Entity` providers.
#[async_trait]
pub trait SimpleEntityProvider: Debug + Send + Sync {
    /// Provides the method signature to `get_entities` from any location.
    async fn get_entities(&self, request: &Request) -> Result<Arc<Entities>, EntityProviderError>;
}

/// `PolicySetProviderError` is a general error that any implementation of trait
/// `SimplePolicySetProvider` can return as an error.
#[derive(Error, Debug)]
pub enum PolicySetProviderError {
    /// A `General` error variant that boxes
    #[error("Policy Set provider failed to get the policy set: {0}")]
    General(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// `SimplePolicySetProvider` trait provides a simple trait for gathering policy set data. Some
/// use cases would be getting data out of a file or a database call.
///
/// The cedar `Request` is passed to the provider as it contains information on the `Principal` trying to
/// perform some `Action` on a `Resource` within some `Context`.  The information contained in this
/// `Request` can be used to gather a slice of a `PolicySet`, i.e. only applicable `Policies` that
/// are related to that specific `Principal`, `Action` or `Resource` based on the implementers algorithm.
#[async_trait]
pub trait SimplePolicySetProvider: Debug + Send + Sync {
    /// Provides the method signature to `get_policy_set` from any location.
    async fn get_policy_set(
        &self,
        request: &Request,
    ) -> Result<Arc<PolicySet>, PolicySetProviderError>;
}

/// `UpdateProviderDataError` occurs when the `SimpleAuthorizer` cannot update the applicable
/// provider's data via an asynchronous background thread.
#[derive(Error, Debug)]
pub enum UpdateProviderDataError {
    /// A `General` error variant that implements debug that boxes other errors
    #[error("Failed to update the provider data: {0}")]
    General(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// `UpdateProviderData` trait provides a simple trait for allowing updating provider data in an
/// async fashion outside the 'request' context of an `is_authorization` question.
#[async_trait]
pub trait UpdateProviderData: Debug + Send + Sync {
    /// Update a providers data within the implementor.
    async fn update_provider_data(&self) -> Result<(), UpdateProviderDataError>;
}
