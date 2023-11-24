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
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use cedar_policy::{PolicySet, Request};
use derive_builder::Builder;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument};

use crate::public::file::content_validator::{BufferReader, BufferReaderError, FileConfig};
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
    #[error("The Policy Set failed to be parsed at path: {0}")]
    PolicySetParseError(String),
    /// Can't read from disk or find the file
    #[error("IO Error: {0}")]
    IOError(#[from] BufferReaderError),
}

/// A wrapper that wraps policy set `ParseError` to map the error message
struct ParseErrorWrapper {
    // This is the path to the file to load the policy set
    policy_set_path: String,
}

/// Implements the constructor for the `ParseErrorWrapper`.
impl ParseErrorWrapper {
    /// Creates a new wrapper of the `ParseErrors`
    fn new(policy_set_path: String) -> Self {
        Self {
            // This is the path to the file to load the policy set
            policy_set_path,
        }
    }
}

/// Map the `ParseErrorWrapper` to the `ProviderError::PolicySetParseError` with the file path
impl From<ParseErrorWrapper> for ProviderError {
    fn from(value: ParseErrorWrapper) -> Self {
        Self::PolicySetParseError(value.policy_set_path)
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
    #[instrument(skip(configuration), err(Debug))]
    pub fn new(configuration: Config) -> Result<Self, ProviderError> {
        let policy_set_path = configuration.policy_set_path;
        let policy_set_src =
            BufferReader::open(&FileConfig::file(policy_set_path.as_str()))?.read_to_string()?;
        let policy_set = PolicySet::from_str(&policy_set_src)
            .map_err(|_parse_errors| ParseErrorWrapper::new(policy_set_path.clone()))?;
        let policy_ids = policy_set
            .policies()
            .map(cedar_policy::Policy::id)
            .collect::<Vec<_>>();
        debug!("Fetched Policy Set from file: file_path={policy_set_path:?}: policy_ids={policy_ids:?}");

        Ok(Self {
            policy_set_path,
            policy_set: RwLock::new(Arc::new(policy_set)),
        })
    }
}

/// Implements the update provider data trait
#[async_trait]
impl UpdateProviderData for PolicySetProvider {
    #[instrument(skip(self), err(Debug))]
    async fn update_provider_data(&self) -> Result<(), UpdateProviderDataError> {
        let policy_set_path = self.policy_set_path.clone();
        let policy_file = BufferReader::open(&FileConfig::file(policy_set_path.as_str()))
            .map_err(|e| UpdateProviderDataError::General(Box::new(ProviderError::IOError(e))))?;

        let policy_set_src = policy_file
            .read_to_string()
            .map_err(|e| UpdateProviderDataError::General(Box::new(ProviderError::IOError(e))))?;

        let policy_set = PolicySet::from_str(&policy_set_src).map_err(|_| {
            UpdateProviderDataError::General(Box::new(ProviderError::PolicySetParseError(
                policy_set_path.clone(),
            )))
        })?;
        {
            let mut policy_set_guard = self.policy_set.write().await;
            *policy_set_guard = Arc::new(policy_set.clone());
        }
        let policy_ids = policy_set
            .policies()
            .map(cedar_policy::Policy::id)
            .collect::<Vec<_>>();
        debug!(
        "Fetched Policy Set from file: file_path={policy_set_path:?}: policy_ids={policy_ids:?}");
        info!("Updated Policy Set Provider");
        Ok(())
    }
}

/// The `PolicySetProvider` returns the entire `PolicySet` read from disk.  The
/// cedar `Request` is unused for this use case.
#[async_trait]
impl SimplePolicySetProvider for PolicySetProvider {
    /// Get Policy set.
    #[instrument(skip_all, err(Debug))]
    async fn get_policy_set(&self, _: &Request) -> Result<Arc<PolicySet>, PolicySetProviderError> {
        Ok(self.policy_set.read().await.clone())
    }
}

#[cfg(test)]
mod test {
    use cedar_policy::{Context, PolicySet, Request};
    use std::io::ErrorKind;
    use std::path::Path;
    use std::str::FromStr;
    use std::{fs, io};
    use tempfile::NamedTempFile;

    use crate::public::file::content_validator::BufferReaderError;
    use crate::public::file::policy_set_provider::ProviderError::PolicySetParseError;
    use crate::public::file::policy_set_provider::{
        ConfigBuilder, PolicySetProvider, ProviderError,
    };
    use crate::public::{SimplePolicySetProvider, UpdateProviderData, UpdateProviderDataError};

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
            "IO Error: IO Error, reason = No such file or directory (os error 2)"
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
        assert_eq!(
            error.err().unwrap().to_string(),
            "The Policy Set failed to be parsed at path: tests/data/malformed_policies.cedar"
        );
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

        let actual = provider
            .unwrap()
            .get_policy_set(&Request::new(
                Some(r#"User::"Adam""#.parse().unwrap()),
                Some(r#"Action::"View""#.parse().unwrap()),
                Some(r#"Box::"10""#.parse().unwrap()),
                Context::empty(),
            ))
            .await
            .unwrap();

        let policy_str = fs::read_to_string(Path::new("tests/data/sweets.cedar")).unwrap();
        let expect = PolicySet::from_str(policy_str.as_str()).unwrap();

        assert_eq!(*actual, expect);
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

    #[tokio::test]
    async fn simple_policy_provider_update_is_parse_error() {
        let temp_file = NamedTempFile::new().unwrap();
        let temp_file_path = temp_file.path().to_str().unwrap().to_string();
        fs::copy("tests/data/sweets.cedar", temp_file_path.clone()).unwrap();

        let provider = PolicySetProvider::new(
            ConfigBuilder::default()
                .policy_set_path(temp_file_path.clone())
                .build()
                .unwrap(),
        );
        assert!(provider.is_ok());

        let policy_set_provider = provider.unwrap();

        fs::copy(
            "tests/data/malformed_policies.cedar",
            temp_file_path.clone(),
        )
        .unwrap();

        let update_result = policy_set_provider.update_provider_data().await;
        assert!(update_result.is_err());
        let update_provider_error = update_result.unwrap_err();

        let UpdateProviderDataError::General(inner_error) = update_provider_error;
        let inner_type = inner_error.downcast_ref::<ProviderError>().unwrap();
        assert!(matches!(inner_type, PolicySetParseError(_)));
    }
    #[tokio::test]
    async fn simple_policy_provider_update_is_io_error() {
        let temp_file = NamedTempFile::new().unwrap();
        let temp_file_path = temp_file.path().to_str().unwrap().to_string();
        let provider = PolicySetProvider::new(
            ConfigBuilder::default()
                .policy_set_path(temp_file_path)
                .build()
                .unwrap(),
        );
        temp_file.close().unwrap();

        let actual = provider.unwrap().update_provider_data().await.unwrap_err();
        let expect = UpdateProviderDataError::General(Box::new(ProviderError::IOError(
            BufferReaderError::IoError(io::Error::new(
                ErrorKind::NotFound,
                "No such file or directory (os error 2)",
            )),
        )));

        assert_eq!(actual.to_string(), expect.to_string());
    }
}
