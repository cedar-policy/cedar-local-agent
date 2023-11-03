//! Provides a simple `SimplePolicySetProvider` and an implementation using a local file system,
//! in the form a `PolicySetProvider`.
//!
//! # Examples
//!
//! ```
//! use cedar_local_agent::public::file::policy_set_provider::{PolicySetProvider, ConfigBuilder};
//!
//! let policy_set_provider = PolicySetProvider::new(
//!      ConfigBuilder::default()
//!         .policy_set_path("some_path")
//!         .build()
//!         .unwrap()
//! );
//! ```
use std::fmt::Debug;
use std::io::Error;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use cedar_policy::{PolicySet, Request};
use cedar_policy_core::parser::err::ParseErrors;
use derive_builder::Builder;
use thiserror::Error;
use tokio::sync::RwLock;

use crate::public::{
    PolicySetProviderError, SimplePolicySetProvider, UpdateProviderData, UpdateProviderDataError,
};

/// `PolicySetProviderConfig` provides the data required to build the
/// `PolicySetProvider`.  Favor the builder to use this object, see example.
///
/// # Examples
///
/// ```
/// use cedar_local_agent::public::file::policy_set_provider::ConfigBuilder;
///
/// let config = ConfigBuilder::default()
///     .policy_set_path("a_path".to_string())
///     .build()
///     .unwrap();
/// ```
#[derive(Default, Builder, Debug)]
#[builder(setter(into))]
pub struct Config {
    /// File path to a policy set
    pub policy_set_path: String,
}

/// `PolicySetProvider` structure implements on the `SimplePolicySetProvider` trait.
#[derive(Debug)]
pub struct PolicySetProvider {
    /// Policy set file path
    policy_set_path: String,
    /// The `policy_set` that is vended to the authorizer
    policy_set: RwLock<Arc<PolicySet>>,
}

/// `ProviderError` thrown by the constructor for the `PolicySetProvider`.
#[derive(Error, Debug)]
pub enum ProviderError {
    /// Policy set file is malformed in some way
    #[error("The Policy Set failed to be parsed: {0}")]
    PolicySetParseError(#[source] ParseErrors),
    /// Can't read from disk or find the file
    #[error("IO Error: {0}")]
    IOError(#[source] std::io::Error),
    /// Failed to update the data async via the update provider
    #[error("The update provider failed to update the entities: {0}")]
    UpdateError(#[source] UpdateProviderDataError),
}

impl From<std::io::Error> for ProviderError {
    fn from(value: Error) -> Self {
        Self::IOError(value)
    }
}

impl From<ParseErrors> for ProviderError {
    fn from(value: ParseErrors) -> Self {
        Self::PolicySetParseError(value)
    }
}

impl PolicySetProvider {
    /// Builds a new `PolicySetProvider`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cedar_local_agent::public::file::policy_set_provider::{ConfigBuilder, PolicySetProvider};
    ///
    /// let policy_set_provider = PolicySetProvider::new(
    ///     ConfigBuilder::default()
    ///         .policy_set_path("some_path".to_string())
    ///         .build()
    ///         .unwrap()
    /// );
    /// ```
    ///
    /// # Errors
    ///
    /// This function can error if the policy set path is invalid or the policy set data is malformed.
    pub fn new(configuration: Config) -> Result<Self, ProviderError> {
        let policy_set_path = configuration.policy_set_path;
        let policy_set_src = std::fs::read_to_string(Path::new(policy_set_path.as_str()))?;
        let policy_set = PolicySet::from_str(&policy_set_src)?;

        Ok(Self {
            policy_set_path,
            policy_set: RwLock::new(Arc::new(policy_set)),
        })
    }
}

/// Implements the update provider data trait
#[async_trait]
impl UpdateProviderData for PolicySetProvider {
    async fn update_provider_data(&self) -> Result<(), UpdateProviderDataError> {
        let policy_set_path = self.policy_set_path.clone();
        let policy_set_src = std::fs::read_to_string(Path::new(policy_set_path.as_str()))
            .map_err(|e| UpdateProviderDataError::General(Box::new(e)))?;
        let policy_set = PolicySet::from_str(&policy_set_src)
            .map_err(|e| UpdateProviderDataError::General(Box::new(e)))?;
        {
            let mut policy_set_guard = self.policy_set.write().await;
            *policy_set_guard = Arc::new(policy_set);
        }

        Ok(())
    }
}

/// The `PolicySetProvider` returns the entire `PolicySet` read from disk.  The
/// cedar `Request` is unused for this use case.
#[async_trait]
impl SimplePolicySetProvider for PolicySetProvider {
    /// Get Policy set.
    async fn get_policy_set(&self, _: &Request) -> Result<Arc<PolicySet>, PolicySetProviderError> {
        Ok(self.policy_set.read().await.clone())
    }
}

#[cfg(test)]
mod test {
    use cedar_policy::{Context, Request};

    use crate::public::file::policy_set_provider::{ConfigBuilder, PolicySetProvider};
    use crate::public::{SimplePolicySetProvider, UpdateProviderData};

    #[test]
    fn simple_policy_provider_is_ok() {
        assert!(PolicySetProvider::new(
            ConfigBuilder::default()
                .policy_set_path("tests/data/sweets.cedar")
                .build()
                .unwrap(),
        )
        .is_ok());
    }

    #[test]
    fn simple_policy_provider_is_io_error() {
        let error = PolicySetProvider::new(
            ConfigBuilder::default()
                .policy_set_path("not_a_file")
                .build()
                .unwrap(),
        );

        assert!(error.is_err());
        assert_eq!(
            error.err().unwrap().to_string(),
            "IO Error: No such file or directory (os error 2)"
        );
    }

    #[test]
    fn simple_policy_provider_is_malformed() {
        let error = PolicySetProvider::new(
            ConfigBuilder::default()
                .policy_set_path("tests/data/malformed_policies.cedar")
                .build()
                .unwrap(),
        );

        assert!(error.is_err());
        assert!(error
            .err()
            .unwrap()
            .to_string()
            .starts_with("The Policy Set failed to be parsed"));
    }

    #[tokio::test]
    async fn simple_policy_provider_get_policy_store_is_ok() {
        let provider = PolicySetProvider::new(
            ConfigBuilder::default()
                .policy_set_path("tests/data/sweets.cedar")
                .build()
                .unwrap(),
        );

        assert!(provider.is_ok());
        assert!(provider
            .unwrap()
            .get_policy_set(&Request::new(
                Some(r#"User::"Adam""#.parse().unwrap()),
                Some(r#"Action::"View""#.parse().unwrap()),
                Some(r#"Box::"10""#.parse().unwrap()),
                Context::empty(),
            ))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn simple_policy_provider_update_is_ok() {
        let provider = PolicySetProvider::new(
            ConfigBuilder::default()
                .policy_set_path("tests/data/sweets.cedar")
                .build()
                .unwrap(),
        );

        assert!(provider.is_ok());
        assert!(provider.unwrap().update_provider_data().await.is_ok());
    }
}
