//! Contains various logging helpers.
use cedar_policy::Entities;
use derive_builder::Builder;

pub mod error;
pub mod event;
pub mod schema;

/// The default requester string will be used in the log line. Unless specified otherwise,
/// all authorizers will employ this name as their default.
pub const DEFAULT_REQUESTER_NAME: &str = "cedar::simple::authorizer";

/// This structure is used to configure the logging system by specifying the log file directory,
/// log file name prefix, log rotation strategy, log rotation format, and meter provider.
#[derive(Debug, Clone, Builder)]
#[builder(setter(into))]
pub struct Config {
    /// `format` is used to specify the log rotation format.
    /// By default the log rotation format is OpenCyberSecurityFramework (OCSF).
    #[builder(default)]
    pub format: Format,

    /// A set specifying which fields are opted-in to be logged
    #[builder(default)]
    pub field_set: FieldSet,

    /// A requester name is used to provide the name of the product and separate the log from
    /// different authorizers
    #[builder(default = "DEFAULT_REQUESTER_NAME.to_string()")]
    pub requester: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            format: Format::default(),
            requester: DEFAULT_REQUESTER_NAME.to_string(),
            field_set: FieldSet::default(),
        }
    }
}

/// This enum is used to specify the log rotation format.
/// The log rotation format is `OpenCyberSecurityFramework` (OCSF)
/// <https://schema.ocsf.io/1.0.0/?extensions=>
#[derive(Default, Eq, PartialEq, Debug, Clone)]
#[non_exhaustive]
pub enum Format {
    /// Default Open Cyber Security Framework format.
    #[default]
    OpenCyberSecurityFramework,
    /// For potentially adding future fields.
    #[non_exhaustive]
    Unknown,
}

#[derive(Builder, Eq, PartialEq, Debug, Clone, Default)]
#[builder(pattern = "owned", default, setter(into))]
#[allow(clippy::struct_excessive_bools)]
/// The `FieldSet` specifies which fields are to be logged
pub struct FieldSet {
    /// A boolean specifying whether the principal field is to be logged
    pub principal: bool,
    /// A boolean specifying whether the resource field is to be logged
    pub resource: bool,
    /// A boolean specifying whether the action field is to be logged
    pub action: bool,
    /// A boolean specifying whether the context field is to be logged
    pub context: bool,
    /// A variant of the `FieldLevel` enum specifying which entity fields are to be logged
    pub entities: FieldLevel<Entities>,
}

/// The `FieldLevel` enum is used to specify which fields are to be logged from a entities object.
/// Choices include `None`, `All`, and `Custom`.
/// The default is `None`.
#[derive(Default, Eq, PartialEq, Debug, Clone)]
#[non_exhaustive]
pub enum FieldLevel<T> {
    #[default]
    /// No fields are logged
    None,
    /// All fields are logged
    All,
    /// Only the provided set of fields are logged.
    Custom(fn(obj: &T) -> T),
    /// For potentially adding future fields.
    #[non_exhaustive]
    Unknown,
}

#[cfg(test)]
mod test {
    use cedar_policy::Entities;

    use crate::public::log::{
        ConfigBuilder, FieldLevel, FieldSet, FieldSetBuilder, Format, DEFAULT_REQUESTER_NAME,
    };

    #[test]
    fn configuration_default() {
        let default_log_configuration = ConfigBuilder::default().build().unwrap();
        assert_eq!(
            default_log_configuration.format,
            Format::OpenCyberSecurityFramework
        );
        assert_eq!(default_log_configuration.requester, DEFAULT_REQUESTER_NAME);
        assert_eq!(default_log_configuration.field_set, FieldSet::default());
    }

    #[test]
    fn configuration_equal() {
        let log_configuration_one = ConfigBuilder::default().build().unwrap();
        let log_configuration_two = ConfigBuilder::default().build().unwrap();
        let log_configuration_three = ConfigBuilder::default()
            .format(Format::OpenCyberSecurityFramework)
            .field_set(FieldSetBuilder::default().principal(true).build().unwrap())
            .build()
            .unwrap();

        assert_eq!(log_configuration_one.format, log_configuration_two.format);
        assert_eq!(
            log_configuration_one.field_set,
            log_configuration_two.field_set
        );
        assert_ne!(
            log_configuration_one.field_set,
            log_configuration_three.field_set
        );
    }

    #[test]
    fn configuration_set_property() {
        let field_set = FieldSetBuilder::default().principal(true).build().unwrap();
        let log_configuration = ConfigBuilder::default()
            .format(Format::OpenCyberSecurityFramework)
            .field_set(field_set.clone())
            .build()
            .unwrap();

        assert_eq!(log_configuration.format, Format::OpenCyberSecurityFramework);
        assert_eq!(log_configuration.field_set, field_set);
    }

    #[test]
    fn field_set_including_all_values_builds() {
        assert!(FieldSetBuilder::default()
            .principal(true)
            .resource(true)
            .action(true)
            .context(true)
            .entities(FieldLevel::All)
            .build()
            .is_ok());
    }

    #[test]
    fn field_set_including_only_default_values_builds() {
        let result = FieldSetBuilder::default().build();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), FieldSet::default());
    }

    #[test]
    fn field_set_including_custom_values_builds() {
        let filter_fn = |entities: &Entities| -> Entities { entities.clone() };
        let result = FieldSetBuilder::default()
            .principal(false)
            .resource(true)
            .action(false)
            .context(false)
            .entities(FieldLevel::Custom(filter_fn))
            .build();
        assert!(result.is_ok());

        let expected = FieldSet {
            principal: false, // explicitly false case
            resource: true,   // explicitly true case
            action: false,    // implicitly false case
            context: false,
            entities: FieldLevel::Custom(filter_fn),
        };
        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn field_set_defaults() {
        let field_set = FieldSet::default();
        assert!(!field_set.context);
        assert!(!field_set.principal);
        assert!(!field_set.action);
        assert!(!field_set.resource);
        assert_eq!(field_set.entities, FieldLevel::None);
    }
}
