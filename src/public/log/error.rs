//! Defines the enum for logging errors returned by the logging builder
use derive_builder::UninitializedFieldError;
use serde_json::Error;
use thiserror::Error;

use crate::public::log::schema::{
    ManagedEntityBuilderError, MetaDataBuilderError, ProductBuilderError,
};

/// `OcsfException` occurs when the authorization request cannot be logged.
#[derive(Error, Debug)]
pub enum OcsfException {
    /// Validation error
    #[error("Ocsf fields validation failed {0}")]
    OcsfFieldsValidationError(String),
    /// Field not initialized
    #[error("All mandatory fields must be provided {0}")]
    UninitializedField(String),
    /// Partial Evaluation
    #[error("Cedar entity result in a residual for partial evaluation")]
    CedarPartialEvaluation,
    /// Serialization error
    #[error("Error occurred during deserializing/serializing {0}")]
    SerdeError(#[source] serde_json::Error),
    /// OCSF conversion failure for product
    #[error("Failed to build Ocsf Product model {0}")]
    OcsfProductBuilderError(#[source] ProductBuilderError),
    /// OCSF conversion failure for metadata
    #[error("Failed to build Ocsf Metadata model {0}")]
    OcsfMetadataBuilderError(#[source] MetaDataBuilderError),
    /// OCSF conversion failure for managed entity
    #[error("Failed to build Ocsf ManagedEntity model {0}")]
    OcsfManagedEntityBuilderError(#[source] ManagedEntityBuilderError),
}

impl From<String> for OcsfException {
    fn from(s: String) -> Self {
        Self::OcsfFieldsValidationError(s)
    }
}

impl From<UninitializedFieldError> for OcsfException {
    fn from(ufe: UninitializedFieldError) -> Self {
        Self::UninitializedField(ufe.to_string())
    }
}

impl From<serde_json::Error> for OcsfException {
    fn from(value: Error) -> Self {
        Self::SerdeError(value)
    }
}

impl From<ProductBuilderError> for OcsfException {
    fn from(value: ProductBuilderError) -> Self {
        Self::OcsfProductBuilderError(value)
    }
}

impl From<MetaDataBuilderError> for OcsfException {
    fn from(value: MetaDataBuilderError) -> Self {
        Self::OcsfMetadataBuilderError(value)
    }
}

impl From<ManagedEntityBuilderError> for OcsfException {
    fn from(value: ManagedEntityBuilderError) -> Self {
        Self::OcsfManagedEntityBuilderError(value)
    }
}

#[cfg(test)]
mod tests {
    use serde::de::Error;

    use crate::public::log::error::OcsfException;
    use crate::public::log::error::OcsfException::OcsfFieldsValidationError;
    use crate::public::log::schema::{
        ManagedEntityBuilderError, MetaDataBuilderError, ProductBuilderError,
    };

    #[test]
    fn test_string_into_ocsf_fields_validation_error() {
        let error_message = "This is the validation error".to_string();
        let validation_error: OcsfException = error_message.clone().into();
        assert_eq!(
            validation_error.to_string(),
            OcsfFieldsValidationError(error_message).to_string()
        );
    }

    #[test]
    fn serde_error_from_logging_exception() {
        let actual = OcsfException::SerdeError(serde_json::Error::custom("serde json error"));
        let expected = OcsfException::from(serde_json::Error::custom("serde json error"));
        assert_eq!(actual.to_string(), expected.to_string());
    }

    #[test]
    fn ocsf_product_builder_error_from_logging_exception() {
        let actual = OcsfException::OcsfProductBuilderError(
            ProductBuilderError::UninitializedField("Foo field not set"),
        );
        let expected =
            OcsfException::from(ProductBuilderError::UninitializedField("Foo field not set"));
        assert_eq!(actual.to_string(), expected.to_string());
    }

    #[test]
    fn ocsf_metadata_builder_error_from_logging_exception() {
        let actual = OcsfException::OcsfMetadataBuilderError(
            MetaDataBuilderError::UninitializedField("Foo field not set"),
        );
        let expected = OcsfException::from(MetaDataBuilderError::UninitializedField(
            "Foo field not set",
        ));
        assert_eq!(actual.to_string(), expected.to_string());
    }

    #[test]
    fn ocsf_managed_entity_builder_error_from_logging_exception() {
        let actual = OcsfException::OcsfManagedEntityBuilderError(
            ManagedEntityBuilderError::UninitializedField("Foo field not set"),
        );
        let expected = OcsfException::from(ManagedEntityBuilderError::UninitializedField(
            "Foo field not set",
        ));
        assert_eq!(actual.to_string(), expected.to_string());
    }
}
