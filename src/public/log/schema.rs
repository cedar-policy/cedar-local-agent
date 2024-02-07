//! Defines the `OpenCyberSecurityFramework` schema and associated types and helpers to convert
//! cedar authorization inputs to a log format.
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::time::Instant;

use cedar_policy::{Diagnostics, Entities, EntityUid, Request, Response};
use chrono::{Local, Utc};
use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::{to_value, Map, Value};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::public::log::error::OcsfException;
use crate::public::log::error::OcsfException::OcsfFieldsValidationError;
use crate::public::log::{FieldLevel, FieldSet};

/// The maximum allowed enrichment array size
const ALLOWED_ENRICHMENT_ARRAY_LEN: usize = 5;
/// The maximum activity name length
const ALLOWED_ACTIVITY_NAME_LEN: usize = 35;

/// The OCSF schema version
const OCSF_SCHEMA_VERSION: &str = "1.0.0";
/// The Log version
const LOG_VERSION: &str = "1.0.0";
/// The vendor name
const VENDOR_NAME: &str = "cedar::simple::authorizer";
/// String used for redaction
const SECRET_STRING: &str = "Sensitive<REDACTED>";

/// A basic Open Cyber Security Framework structure
/// Entity Management events report activity. The activity can be a
/// create, read, update, and delete operation on a managed entity.
/// <https://schema.ocsf.io/1.0.0/classes/entity_management?extensions=>
#[derive(Default, Builder, Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
#[builder(
    setter(into),
    build_fn(validate = "Self::validate_ocsf_fields", error = "OcsfException")
)]
pub struct OpenCyberSecurityFramework {
    /// The event activity name, as defined by the `activity_id`
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activity_name: Option<String>,
    /// The activity id enum
    pub activity_id: ActivityId,
    /// The event category name, as defined by `category_uid` value: Identity & Access Management
    #[builder(default = "Some(\"Identity & Access Management\".to_string())")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category_name: Option<String>,
    /// The category unique identifier of the event. The authorization log will always be 3
    #[builder(default = "3u8")]
    pub category_uid: u8,
    /// The event class name, as defined by class_uid value: `Entity Management`
    #[builder(default = "Some(\"Entity Management\".to_string())")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_name: Option<String>,
    /// The unique identifier of a class. By default, the value is set to 3004
    #[builder(default = "3004u64")]
    pub class_uid: u64,
    /// The user provided comment about why the entity was changed
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// The number of times that events in the same logical group occurred during the event Start
    /// time to End Time period.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    /// The event duration or aggregate time, the amount of time the event covers from start_time to end_time in milliseconds
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<i64>,
    /// The end time of a time period, or the time of the most recent event included in the aggregate event
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<i64>,
    /// The additional information from an external data source, which is associated with the event
    /// for example add location information for the IP address.
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrichments: Option<Vec<EnrichmentArray>>,
    /// The principal entity that is sending the request
    pub entity: ManagedEntity,
    /// The resource entity that is being acted upon
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_result: Option<ManagedEntity>,
    /// The timestamp value indicating the time of the event occurrence in UTC
    pub time: i64,
    /// The event description will either display an error message if one exists, or
    /// provide detailed information on how the request was authorized in the absence of an error
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The metadata associated with the event such as the `log_provider`
    pub metadata: MetaData,
    /// The observables associated with the event
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observables: Option<Vec<Observable>>,
    /// The event data as received from the event source
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_data: Option<String>,
    /// The event severity, normalized to the caption of the severity_id value
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// The normalized identifier of the event severity
    pub severity_id: SeverityId,
    /// The start time of an event
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<i64>,
    /// The event status, normalized to the caption of the status_id value
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// The event status code, as reported by the event source
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<String>,
    /// The status details contains additional information about the event outcome
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_detail: Option<String>,
    /// The normalized identifier of the event status
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_id: Option<StatusId>,
    /// The number of minutes that the reported event time is ahead or behind UTC,
    /// in the range -1,080 to +1,080
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone_offset: Option<i32>,
    /// The event type ID. It identifies the event's semantics and structure.
    /// the value is calculated by the logging system as: class_uid * 100 + activity_id
    pub type_uid: TypeUid,
    /// The event type name, as defined by the type_uid
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
    /// The attributes that are not mapped to the event schema.
    /// the names and values of those attributes are specific to the event source
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unmapped: Option<Value>,
}

impl OpenCyberSecurityFramework {
    /// Converts Request, Entities, Field Set into a filtered OCSF log.
    ///
    /// # Errors
    ///
    /// Will return `OcsfException` if `ProductBuilder`, `MetaDataBuilder`, `ManagedEntityBuilder`
    /// failed to build the models, Serde failed to deserializing the object, Cedar residual
    /// evaluation request and any model validation error
    pub fn create(
        request: &Request,
        response: &Response,
        entities: &Entities,
        fields: &FieldSet,
        authorizer_name: &str,
    ) -> Result<Self, OcsfException> {
        let decision = response.decision();
        return OpenCyberSecurityFramework::create_generic(
            request,
            response.diagnostics(),
            format!("decision is {decision:?}").as_str(),
            format!("{decision:?}"),
            entities,
            fields,
            authorizer_name
        )
    }

    /// Converts Request, Entities, Field Set into a filtered OCSF log.
    ///
    /// # Errors
    ///
    /// Will return `OcsfException` if `ProductBuilder`, `MetaDataBuilder`, `ManagedEntityBuilder`
    /// failed to build the models, Serde failed to deserializing the object and any model validation error
    pub fn create_generic(
        request: &Request,
        diagnostics: &Diagnostics,
        outcome: &str,
        status_code: String,
        entities: &Entities,
        fields: &FieldSet,
        authorizer_name: &str,
    ) -> Result<Self, OcsfException> {
        let filtered_request = filter_request(request, entities, fields);
        let start_time = Instant::now();

        let mut unmapped = Map::new();
        if let Some(context_str) = filtered_request.clone().context {
            unmapped.insert("context".to_string(), to_value(context_str)?);
        } else {
            unmapped.insert("context".to_string(), to_value(SECRET_STRING)?);
        }

        // Cedar will return None when the evaluation is only partial. This check will raise an error
        // and not continue to obtain the entity information below. Consider remove this check after
        // this issue resolved. https://github.com/cedar-policy/cedar/issues/72
        let principal = filtered_request.principal.get_id()?;
        let action = filtered_request.action.get_id()?;
        let resource = filtered_request.resource.get_id()?;

        let reasons: Vec<String> = diagnostics
            .reason()
            .map(ToString::to_string)
            .collect();
        unmapped.insert(
            "determined_policies".to_string(),
            to_value(reasons.clone())?,
        );

        let response_error: Vec<String> = diagnostics
            .errors()
            .map(std::string::ToString::to_string)
            .collect();
        unmapped.insert(
            "evaluation_errors".to_string(),
            to_value(response_error.clone())?,
        );

        let (status_id, status, status_details);

        if response_error.is_empty() {
            status_id = StatusId::Success;
            status = "Success".to_string();
            status_details = reasons.join(",");
        } else {
            status_id = StatusId::Failure;
            status = "Failure".to_string();
            status_details = response_error.join(",");
        }

        let message = format!(
            "Principal {principal} performed action \
                {action} on {resource}, the {outcome} \
                determined by policy id {reasons:?} and errors {response_error:?}",
        );

        let product = ProductBuilder::default()
            .vendor_name(VENDOR_NAME)
            .name(authorizer_name.to_string())
            .lang("en".to_string())
            .build()?;

        let (severity_id, severity) = build_ocsf_severity(response_error.len());

        let source_entity =
            generate_managed_entity(&filtered_request.entities, &filtered_request.principal)?;
        let resource_entity =
            generate_managed_entity(&filtered_request.entities, &filtered_request.resource)?;
        let action_entity =
            generate_managed_entity(&filtered_request.entities, &filtered_request.action)?;
        unmapped.insert(
            "action_entity_details".to_string(),
            to_value(action_entity)?,
        );

        let timezone_offset = Local::now().offset().local_minus_utc() / 60;

        let activity_id = ActivityId::from(action.to_string());
        let type_uid = TypeUid::from(activity_id.clone());

        let metadata = MetaDataBuilder::default()
            .version(OCSF_SCHEMA_VERSION)
            .product(product)
            .log_provider(VENDOR_NAME.to_string())
            .logged_time(Utc::now().timestamp())
            .log_version(LOG_VERSION.to_string())
            .processed_time(start_time.elapsed().as_millis())
            .build()?;

        OpenCyberSecurityFrameworkBuilder::default()
            .activity_name(action)
            .activity_id(activity_id)
            .entity(source_entity)
            .entity_result(resource_entity)
            .message(message)
            .type_uid(type_uid.clone())
            .type_name(type_uid.to_string())
            .severity(severity)
            .severity_id(severity_id)
            .metadata(metadata)
            .time(Utc::now().timestamp())
            .timezone_offset(timezone_offset)
            .status_id(status_id)
            .status(status)
            .status_detail(status_details)
            .status_code(status_code)
            .unmapped(to_value(unmapped)?)
            .build()
    }

    /// A default error implementation provided.
    pub fn error(error_message: String, authorizer_name: String) -> Self {
        let product = ProductBuilder::default()
            .vendor_name(VENDOR_NAME)
            .name(authorizer_name)
            .build()
            .unwrap_or_default();

        return OpenCyberSecurityFrameworkBuilder::default()
            .type_uid(TypeUid::Other)
            .severity_id(SeverityId::Other)
            .metadata(
                MetaDataBuilder::default()
                    .version(OCSF_SCHEMA_VERSION)
                    .product(product)
                    .build()
                    .unwrap_or_default(),
            )
            .time(Utc::now().timestamp())
            .entity(
                ManagedEntityBuilder::default()
                    .name("N/A".to_string())
                    .build()
                    .unwrap_or_default(),
            )
            .activity_id(ActivityId::Other)
            .message(error_message)
            .build()
            .unwrap_or_default();
    }
}

fn filter_request(request: &Request, entities: &Entities, fields: &FieldSet) -> FilteredRequest {
    let mut builder = FilteredRequestBuilder::default();

    if fields.principal {
        builder.principal(request.principal().cloned());
    };
    if fields.action {
        builder.action(request.action().cloned());
    }
    if fields.resource {
        builder.resource(request.resource().cloned());
    }

    // Since there is no `Context` getter on the `Request`, instead return `request.to_string()`
    // which includes the context.
    if fields.context {
        builder.context(request.to_string());
    }

    let entities = match fields.entities {
        FieldLevel::All => Some(entities.clone()),
        FieldLevel::Custom(filter_fn) => Some(filter_fn(entities)),
        FieldLevel::None | FieldLevel::Unknown => None,
    };

    builder.entities(entities);
    builder.build().unwrap_or_default()
}

fn generate_managed_entity(
    entities: &Option<Entities>,
    component: &EntityComponent,
) -> Result<ManagedEntity, OcsfException> {
    // The map contains the useful information of entity. For now, it only contains the ancestors
    // information and could add more in the future such as entity attributes.
    let mut entity_details_map = Map::new();

    let mut parents = Vec::<String>::new();
    if let EntityComponent::Concrete(entity_uid) = component {
        parents = entities.as_ref().map_or_else(Vec::<String>::new, |e| {
            e.ancestors(entity_uid)
                .map_or_else(Vec::<String>::new, |e| e.map(ToString::to_string).collect())
        });
    }

    entity_details_map.insert("Parents".to_string(), to_value(parents)?);
    Ok(ManagedEntityBuilder::default()
        .name(component.get_id()?)
        .entity_type(component.get_type_name()?)
        .data(to_value(entity_details_map)?)
        .build()?)
}

fn build_ocsf_severity(num_of_errors: usize) -> (SeverityId, String) {
    match num_of_errors {
        0 => (SeverityId::Informational, "Informational".to_string()),
        1 => (SeverityId::Low, "Low".to_string()),
        _ => (SeverityId::Medium, "Medium".to_string()),
    }
}

impl OpenCyberSecurityFrameworkBuilder {
    /// Validates inputs to the builder for potential denial of service length inputs.
    ///
    /// # Errors
    ///
    /// If the `OpenCyberSecurityFrameworkBuilder` does not pass validation checks, like exceeding
    /// the maximum allowed length for the `activity_name`, it will result in an `OcsfFieldsValidationError`.
    fn validate_ocsf_fields(&self) -> Result<(), OcsfException> {
        let is_enrichments_valid: bool = self.enrichments.as_ref().map_or(true, |enrichments| {
            enrichments
                .as_ref()
                .map_or(true, |vec| vec.len() < ALLOWED_ENRICHMENT_ARRAY_LEN)
        });

        let is_activity_name_valid: bool =
            self.activity_name.as_ref().map_or(true, |activity_name| {
                activity_name
                    .as_ref()
                    .map_or(true, |s| s.len() < ALLOWED_ACTIVITY_NAME_LEN)
            });

        if is_enrichments_valid && is_activity_name_valid {
            Ok(())
        } else {
            Err(OcsfFieldsValidationError(format!(
                "Either the Enrichments array exceeds the maximum allowed size of \
	                 {ALLOWED_ENRICHMENT_ARRAY_LEN} elements, or the Activity name exceeds the \
	                 maximum allowed length of {ALLOWED_ACTIVITY_NAME_LEN} characters... "
            )))
        }
    }
}

/// The normalized identifier of the activity that triggered the event
#[derive(Debug, Serialize_repr, Deserialize_repr, Clone, Eq, PartialEq, Default)]
#[repr(u8)]
pub enum ActivityId {
    /// The event is unknown
    #[default]
    Unknown = 0,
    /// The activity is creating some resources
    Create = 1,
    /// The activity is read-only operation
    Read = 2,
    /// The activity is updating existing resource
    Update = 3,
    /// The activity is deleting resource
    Delete = 4,
    /// The event activity is not mapped
    Other = 99,
}

/// The 1 to 1 mapping of `activity_name` to the `ActivityId`
impl From<String> for ActivityId {
    fn from(activity_name: String) -> Self {
        let activity_name_lower_case = activity_name.to_lowercase();

        match activity_name_lower_case.as_str() {
            "read" => Self::Read,
            "update" => Self::Update,
            "delete" => Self::Delete,
            "unknown" => Self::Unknown,
            _ => Self::Other,
        }
    }
}

/// The normalized severity is a measurement the effort and expense required to manage and resolve
/// an event or incident
#[derive(Debug, Serialize_repr, Deserialize_repr, Clone, Eq, PartialEq, Default)]
#[repr(u8)]
pub enum SeverityId {
    /// The event severity is not known
    #[default]
    Unknown = 0,
    /// Informational message. No action required
    Informational = 1,
    /// The user decides if action is needed
    Low = 2,
    /// Action is required but the situation is not serious at this time
    Medium = 3,
    /// Action is required immediately
    High = 4,
    /// Action is required immediately and the scope is broad
    Critical = 5,
    /// An error occurred but it is too late to take remedial action
    Fatal = 6,
    /// The event severity is not mapped. See the severity attribute, which contains a data source specific value
    Other = 99,
}

/// The normalized identifier of the event status
#[derive(Debug, Serialize_repr, Deserialize_repr, Clone, Eq, PartialEq, Default)]
#[repr(u8)]
pub enum StatusId {
    /// The status is unknown
    #[default]
    Unknown = 0,
    /// The event was successful
    Success = 1,
    /// The event failed
    Failure = 2,
    /// The event status is not mapped
    Other = 99,
}

/// The event type ID. It identifies the event's semantics and structure
#[derive(Debug, Serialize_repr, Deserialize_repr, Clone, Eq, PartialEq, Default)]
#[repr(u64)]
pub enum TypeUid {
    /// The status is unknown
    #[default]
    Unknown = 300_400,
    /// Create activity
    Create = 300_401,
    /// Read activity
    Read = 300_402,
    /// Update activity
    Update = 300_403,
    /// Delete activity
    Delete = 300_404,
    /// Other activity
    Other = 300_499,
}

/// Enables an easy way to call `to_string` on `TypeUid`.
impl fmt::Display for TypeUid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Map the `ActivityId` to `TypeUid`. They have the same category but different values
impl From<ActivityId> for TypeUid {
    fn from(activity_id: ActivityId) -> Self {
        match activity_id {
            ActivityId::Unknown => Self::Unknown,
            ActivityId::Create => Self::Create,
            ActivityId::Read => Self::Read,
            ActivityId::Update => Self::Update,
            ActivityId::Delete => Self::Delete,
            ActivityId::Other => Self::Other,
        }
    }
}

/// The observable value type identifier
#[derive(Debug, Serialize_repr, Deserialize_repr, Clone, Eq, PartialEq, Default)]
#[repr(u8)]
pub enum ObservableTypeId {
    /// Unknown observable data type
    #[default]
    Unknown = 0,
    /// Unique name assigned to a device connected to a computer network
    Hostname = 1,
    /// Internet Protocol address (IP address), in either IPv4 or IPv6 format
    IPAddress = 2,
    /// Media Access Control (MAC) address. For example: 18:36:F3:98:4F:9A
    MACAddress = 3,
    /// User name. For example: john_doe
    UserName = 4,
    /// Email address. For example: john_doe@example.com
    EmailAddress = 5,
    /// Uniform Resource Locator (URL) string
    URLString = 6,
    /// File name. For example: text-file.txt
    FileName = 7,
    /// File hash. A unique value that corresponds to the content of the file
    FileHash = 8,
    /// Process name. For example: Notepad
    ProcessName = 9,
    /// Resource unique identifier. For example, S3 Bucket name or EC2 Instance ID
    ResourceUID = 10,
    /// Endpoints, whether physical or virtual, connect to and interact with computer networks.
    /// Examples include mobile devices, computers, virtual machines, embedded devices, servers,
    /// and IoT devices like cameras and smart speakers
    Endpoint = 20,
    /// The User object describes the characteristics of a user/person or a security principal.
    /// Defined by D3FEND [d3f:UserAccount](https://d3fend.mitre.org/dao/artifact/d3f:UserAccount/)
    User = 21,
    /// The Email object describes the email metadata such as sender, recipients, and direction.
    /// Defined by D3FEND [d3f:Email](https://d3fend.mitre.org/dao/artifact/d3f:Email/)
    Email = 22,
    /// The Uniform Resource Locator(URL) object describes the characteristics of a URL.
    /// Defined in RFC 1738 and by D3FEND [d3f:URL](https://d3fend.mitre.org/dao/artifact/d3f:URL/)
    UniformResourceLocator = 23,
    /// The File object represents the metadata associated with a file stored in a computer system.
    ///Defined by D3FEND [d3f:File](https://next.d3fend.mitre.org/dao/artifact/d3f:File/)
    File = 24,
    /// The Process object describes a running instance of a launched program.
    /// Defined by D3FEND [d3f:Process](https://d3fend.mitre.org/dao/artifact/d3f:Process/)
    Process = 25,
    /// The Geo Location object describes a geographical location, usually associated with an IP address.
    /// Defined by D3FEND [d3f:PhysicalLocation](https://d3fend.mitre.org/dao/artifact/d3f:PhysicalLocation/)
    GeoLocation = 26,
    /// The Container object describes an instance of a specific container
    Container = 27,
    /// The registry key object describes a Windows registry key.
    /// Defined by D3FEND [d3f:WindowsRegistryKey](https://d3fend.mitre.org/dao/artifact/d3f:WindowsRegistryKey/)
    RegistryKey = 28,
    /// The registry value object describes a Windows registry value
    RegistryValue = 29,
    /// The Fingerprint object provides detailed information about a digital fingerprint,
    /// which is a compact representation of data used to identify a longer piece of information,
    /// such as a public key or file content
    Fingerprint = 30,
    /// The observable data type is not mapped
    Other = 99,
}

/// The Reputation object describes the reputation/risk score of an entity (e.g. device, user, domain)
#[derive(Debug, Serialize_repr, Deserialize_repr, Clone, Eq, PartialEq, Default)]
#[repr(u8)]
pub enum ReputationScoreId {
    /// Unknown
    #[default]
    Unknown = 0,
    /// Long history of good behavior
    VerySafe = 1,
    /// Consistently good behavior
    Safe = 2,
    /// No bad behavior
    ProbablySafe = 3,
    /// Reasonable history of good behavior
    LeansSafe = 4,
    /// Starting to establish a history behavior
    MayNotBeSafe = 5,
    /// No established history of normal behavior
    ExerciseCaution = 6,
    /// Starting to establish a history of suspicious or risky behavior
    SuspiciousRisky = 7,
    /// A site with a history of suspicious or risky behavior.
    /// (spam, scam, potentially unwanted software, potentially malicious)
    PossiblyMalicious = 8,
    /// Strong possibility of maliciousness
    ProbablyMalicious = 9,
    /// Indicators of maliciousness
    Malicious = 10,
    /// Proven evidence of maliciousness
    Other = 99,
}

/// The additional information from an external data source, which is associated with the event.
/// <https://schema.ocsf.io/1.0.0/objects/enrichment?extensions=>
#[derive(Default, Serialize, Deserialize, Builder, Eq, PartialEq, Debug, Clone)]
#[builder(setter(into))]
pub struct EnrichmentArray {
    /// The enrichment data associated with the attribute and value
    pub data: HashMap<String, Vec<String>>,
    /// The name of the attribute to which the enriched data pertains
    pub name: String,
    /// The value of the attribute to which the enriched data pertains
    pub value: String,
    /// The enrichment data provider name
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The enrichment type. For example: location
    #[serde(rename = "type")]
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrichment_type: Option<String>,
}

/// A pivot element that contains related information found in many places in the event.
/// <https://schema.ocsf.io/1.0.0/objects/observable?extensions=>
#[derive(Default, Serialize, Deserialize, Builder, Eq, PartialEq, Debug, Clone)]
#[builder(setter(into))]
pub struct Observable {
    /// The observable value type identifier
    pub type_id: ObservableTypeId,
    /// The full name of the observable attribute
    pub name: String,
    /// The value associated with the observable attribute. The meaning of the value depends on
    /// the observable type
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// The observable value type name
    #[serde(rename = "type")]
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observable_type: Option<String>,
    /// Contains the original and normalized reputation scores
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reputation: Option<Reputation>,
}

/// Describes the reputation/risk score of an entity (e.g. device, user, domain).
/// <https://schema.ocsf.io/1.0.0/objects/reputation?extensions=>
#[derive(Default, Serialize, Deserialize, Builder, Eq, PartialEq, Debug, Clone)]
#[builder(setter(into))]
pub struct Reputation {
    /// The normalized reputation score identifier
    pub score_id: ReputationScoreId,
    /// The reputation score as reported by the event source
    pub base_score: u8,
    /// The provider of the reputation information
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The reputation score, normalized to the caption of the score_id value. In the case of 'Other',
    /// it is defined by the event source
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<String>,
}

/// The managed entity that is being acted upon.
/// <https://schema.ocsf.io/1.0.0/objects/managed_entity?extensions=>
#[derive(Default, Serialize, Deserialize, Builder, Eq, PartialEq, Debug, Clone)]
#[builder(setter(into))]
pub struct ManagedEntity {
    /// The managed entity content as a JSON object
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    /// The name of the managed entity
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The managed entity namespace
    #[serde(rename = "type")]
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_type: Option<String>,
    /// The identifier of the managed entity
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unique_id: Option<String>,
    /// The version of the managed entity
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Describes the metadata associated with the event
/// <https://schema.ocsf.io/1.0.0/objects/metadata?extensions=>
#[derive(Default, Serialize, Deserialize, Builder, Eq, PartialEq, Debug, Clone)]
#[builder(setter(into))]
pub struct MetaData {
    /// The version of the OCSF schema
    pub version: String,
    /// The product that reported the event
    pub product: Product,
    /// The original event time as reported by the event source. Omit if event is generated instead
    /// of collected via logs
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_time: Option<String>,
    /// The logging provider or logging service that logged the event
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_provider: Option<String>,
    /// The event log name
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_name: Option<String>,
    /// Sequence number of the event. The sequence number is a value available in some events,
    /// to make the exact ordering of events unambiguous, regardless of the event time precision
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    /// The schema extension used to create the event
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extension: Option<Extension>,
    /// The list of profiles used to create the event
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profiles: Option<Vec<String>>,
    /// The event processed time, such as an ETL operation
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processed_time: Option<u128>,
    /// The time when the event was last modified or enriched
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_time: Option<i64>,
    /// The time when the logging system collected and logged the event
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logged_time: Option<i64>,
    /// The event log schema version that specifies the format of the original event
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_version: Option<String>,
    // The list of category labels attached to the event or specific attributes
    /// Labels are user defined tags or aliases added at normalization time
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    /// The logging system-assigned unique identifier of an event instance
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// The Event ID or Code that the product uses to describe the event
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_code: Option<String>,
    /// The unique identifier used to correlate events
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_uid: Option<String>,
}

/// Describes characteristics of a software product.
/// <https://schema.ocsf.io/1.0.0/objects/product?extensions=>
#[derive(Default, Serialize, Deserialize, Builder, Eq, PartialEq, Debug, Clone)]
#[builder(setter(into))]
pub struct Product {
    /// The name of the vendor of the product
    pub vendor_name: String,
    /// The version of the product, as defined by the event source
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The unique identifier of the product
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// The name of the product
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The two letter lower case language codes. For example, en(English)
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    /// The URL pointing towards the product
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url_string: Option<String>,
    /// The installation path of the product
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The feature that reported the event
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature: Option<Feature>,
}

/// Encompasses details related to the capabilities, components, user interface (UI) design,
/// and performance upgrades associated with the feature.
/// <https://schema.ocsf.io/1.0.0/objects/feature?extensions=>
#[derive(Default, Serialize, Deserialize, Builder, Eq, PartialEq, Debug, Clone)]
#[builder(setter(into))]
pub struct Feature {
    /// The name of the feature
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The unique identifier of the feature
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    /// The version of the feature
    #[builder(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Detailed information about the schema extension used to construct the event
/// <https://schema.ocsf.io/1.0.0/objects/extension?extensions=>
#[derive(Default, Serialize, Deserialize, Builder, Eq, PartialEq, Debug, Clone)]
#[builder(setter(into))]
pub struct Extension {
    /// The schema extension name. For example: dev
    pub name: String,
    /// The schema extension unique identifier. For example: 999
    pub uid: String,
    /// The schema extension version. For example: 1.0.0-alpha.2
    pub version: String,
}

/// `FilteredRequest` provides a mechanism to filter out specific parts of an authorization
/// decision from being logged within the event.
#[derive(Default, Debug, Clone, Builder)]
#[builder(setter(into), default)]
struct FilteredRequest {
    pub principal: EntityComponent,
    pub action: EntityComponent,
    pub resource: EntityComponent,
    pub context: Option<String>,
    pub entities: Option<Entities>,
}

/// `EntityComponent` typically represents a principal, action or resource within an
/// authorization decision.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub(crate) enum EntityComponent {
    /// A concrete EntityUID
    Concrete(EntityUid),
    /// An EntityUID left as unknown for partial evaluation
    Unknown,
    #[default]
    /// No EntityUID because it was filtered out.
    None,
}

impl Display for EntityComponent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Concrete(euid) => {
                write!(f, "{}", euid.id())
            }
            Self::None => {
                write!(f, "{SECRET_STRING}")
            }
            Self::Unknown => {
                write!(f, "partial evaluation")
            }
        }
    }
}

impl EntityComponent {
    /// Gets the component types name.
    ///
    /// # Errors
    ///
    /// Cedar will return None when the evaluation is only partial. `get_type_name()` will raise an error
    /// Consider remove this check after this [issue](https://github.com/cedar-policy/cedar/issues/72) resolved.
    pub fn get_type_name(&self) -> Result<String, OcsfException> {
        match self {
            Self::Concrete(euid) => Ok(euid.type_name().to_string()),
            Self::Unknown => Err(OcsfException::CedarPartialEvaluation),
            Self::None => Ok(SECRET_STRING.to_string()),
        }
    }

    /// Gets the Id of the component.
    ///
    /// # Errors
    ///
    /// Will return `CedarPartialEvaluation` if cedar result in a residual for partial evaluation
    pub fn get_id(&self) -> Result<String, OcsfException> {
        match self {
            Self::Concrete(euid) => Ok(euid.id().to_string()),
            Self::Unknown => Err(OcsfException::CedarPartialEvaluation),
            Self::None => Ok(SECRET_STRING.to_string()),
        }
    }
}

impl From<Option<EntityUid>> for EntityComponent {
    fn from(value: Option<EntityUid>) -> Self {
        value.map_or_else(|| Self::Unknown, Self::Concrete)
    }
}

#[cfg(test)]
mod test {
    use std::collections::{HashMap, HashSet};
    use std::str::FromStr;

    use cedar_policy::{
        AuthorizationError, Context, Entities, EntityId, EntityTypeName, EntityUid,
        EvaluationError, PolicyId, Request, Response,
    };
    use cedar_policy_core::ast::{PolicyID, RestrictedExprError, Value};
    use cedar_policy_core::authorizer::Decision;
    use serde_json::{from_str, to_string, to_value, Map};

    use crate::public::log::error::OcsfException;
    use crate::public::log::error::OcsfException::{OcsfFieldsValidationError, UninitializedField};
    use crate::public::log::schema::{
        filter_request, ActivityId, EnrichmentArray, EnrichmentArrayBuilder, EntityComponent,
        ManagedEntity, ManagedEntityBuilder, MetaData, MetaDataBuilder, OpenCyberSecurityFramework,
        OpenCyberSecurityFrameworkBuilder, ProductBuilder, SeverityId, TypeUid,
        ALLOWED_ACTIVITY_NAME_LEN, ALLOWED_ENRICHMENT_ARRAY_LEN, OCSF_SCHEMA_VERSION, VENDOR_NAME,
    };
    use crate::public::log::{FieldLevel, FieldSet, FieldSetBuilder};

    fn generate_metadata() -> MetaData {
        return MetaDataBuilder::default()
            .version("1.0.0")
            .product(
                ProductBuilder::default()
                    .vendor_name("cedar-local-agent")
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
    }

    fn generate_entity(entity_type: String, name: String) -> ManagedEntity {
        return ManagedEntityBuilder::default()
            .version("1.0.0".to_string())
            .entity_type(entity_type)
            .name(name)
            .build()
            .unwrap();
    }

    fn generate_default_ocsf_model() -> OpenCyberSecurityFramework {
        return OpenCyberSecurityFrameworkBuilder::default()
            .type_uid(TypeUid::Read)
            .severity_id(SeverityId::Unknown)
            .metadata(generate_metadata())
            .time(1_695_275_741_i64)
            .entity(generate_entity("user".to_string(), "alice".to_string()))
            .activity_id(ActivityId::Read)
            .build()
            .unwrap();
    }

    fn generate_validation_error() -> Result<OpenCyberSecurityFramework, OcsfException> {
        Err(OcsfFieldsValidationError(format!(
            "Either the Enrichments array exceeds the maximum allowed size of \
	                 {ALLOWED_ENRICHMENT_ARRAY_LEN} elements, or the Activity name exceeds the \
	                 maximum allowed length of {ALLOWED_ACTIVITY_NAME_LEN} characters... "
        )))
    }

    fn generate_enrichment_array_vec(num_items: usize) -> Vec<EnrichmentArray> {
        (0..num_items).map(|_| EnrichmentArray::default()).collect()
    }

    fn generate_entity_uid(entity_id: &str) -> EntityUid {
        EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("CedarLocalAgent::User").unwrap(),
            EntityId::from_str(entity_id).unwrap(),
        )
    }

    fn generate_mock_request(principal_name: &str) -> Request {
        let principal = Some(generate_entity_uid(principal_name));
        let action = Some(generate_entity_uid("read"));
        let resource = Some(generate_entity_uid("Box"));

        Request::new(principal, action, resource, Context::empty(), None).unwrap()
    }

    fn generate_entities() -> Entities {
        let entities_data = r#"
        [
          {
            "uid": { "type": "CedarLocalAgent::User", "id": "alice" },
            "attrs": {},
            "parents": [
              { "type": "CedarLocalAgent::UserGroup", "id": "alice_friends" },
              { "type": "CedarLocalAgent::UserGroup", "id": "bob_friends" }
            ]
          },
          {
            "uid": { "type": "CedarLocalAgent::User", "id": "bob"},
            "attrs" : {},
            "parents": []
          }
        ]"#;
        Entities::from_json_str(entities_data, None).unwrap()
    }

    fn generate_custom_count_entities(count: i32) -> Entities {
        let mut entities_data = r#"
        [
          {
            "uid": { "type": "CedarLocalAgent::User", "id": "alice" },
            "attrs": {},
            "parents": [
              { "type": "CedarLocalAgent::UserGroup", "id": "alice_friends" },
              { "type": "CedarLocalAgent::UserGroup", "id": "bob_friends" }
            ]
          },
          "#
        .to_owned();
        for i in 0..count {
            let append = r#"{
                "uid": { "type": "CedarLocalAgent::User", "id": "bob"#
                .to_owned()
                + i.to_string().as_str()
                + r#""},
                "attrs" : {},
                "parents": []
               },"#;

            entities_data.push_str(&append);
        }
        entities_data.pop(); // To remove the final comma (from_json_str throws an error otherwise)
        entities_data.push(']');

        Entities::from_json_str(&entities_data, None).unwrap()
    }

    fn generate_response(num_of_error: usize, decision: Decision) -> Response {
        let mut policy_ids = HashSet::new();
        policy_ids.insert(PolicyId::from_str("policy1").unwrap());
        policy_ids.insert(PolicyId::from_str("policy2").unwrap());

        let errors = (0..num_of_error)
            .map(|i| AuthorizationError::PolicyEvaluationError {
                id: PolicyID::from_string(format!("policy{i}")),
                error: EvaluationError::from(RestrictedExprError::InvalidRestrictedExpression {
                    feature: Default::default(),
                    expr: Value::from(true).into(),
                }),
            })
            .collect();

        Response::new(decision, policy_ids, errors)
    }

    #[test]
    fn ocsf_field_mapping_allow_case() {
        let request = generate_mock_request("alice");
        let entities = generate_entities();
        let response = generate_response(0, Decision::Allow);
        let ocsf = OpenCyberSecurityFramework::create(
            &request,
            &response,
            &entities,
            &FieldSet::default(),
            "cedar::local::agent::library",
        );
        assert!(ocsf.is_ok());
        let ocsf_log = ocsf.unwrap();
        assert_eq!(ocsf_log.severity_id, SeverityId::Informational);
        assert_eq!(ocsf_log.status.unwrap(), "Success".to_string());
        assert_eq!(ocsf_log.status_code.unwrap(), "Allow".to_string());
    }

    #[test]
    fn ocsf_field_mapping_deny_case() {
        let request = generate_mock_request("alice");
        let entities = generate_entities();
        let response = generate_response(1, Decision::Deny);
        let ocsf = OpenCyberSecurityFramework::create(
            &request,
            &response,
            &entities,
            &FieldSet::default(),
            "cedar::local::agent::library",
        );
        assert!(ocsf.is_ok());
        let ocsf_log = ocsf.unwrap();
        assert_eq!(ocsf_log.severity_id, SeverityId::Low);
        assert_eq!(ocsf_log.status.unwrap(), "Failure".to_string());

        let response = generate_response(2, Decision::Deny);
        let ocsf = OpenCyberSecurityFramework::create(
            &request,
            &response,
            &entities,
            &FieldSet::default(),
            "cedar::local::agent::library",
        );

        assert!(ocsf.is_ok());
        let ocsf_log = ocsf.unwrap();
        assert_eq!(ocsf_log.severity_id, SeverityId::Medium);
        assert_eq!(ocsf_log.status.unwrap(), "Failure".to_string());
        assert_eq!(ocsf_log.status_code.unwrap(), "Deny".to_string());
    }

    #[test]
    fn activity_id_conversion() {
        assert_eq!(ActivityId::from("update".to_string()), ActivityId::Update);
        assert_eq!(ActivityId::from("delete".to_string()), ActivityId::Delete);
        assert_eq!(ActivityId::from("unknown".to_string()), ActivityId::Unknown);
        assert_eq!(
            ActivityId::from("any_other_activity".to_string()),
            ActivityId::Other
        );
    }

    #[test]
    fn type_uid_conversion() {
        assert_eq!(TypeUid::from(ActivityId::Update), TypeUid::Update);
        assert_eq!(TypeUid::from(ActivityId::Delete), TypeUid::Delete);
        assert_eq!(TypeUid::from(ActivityId::Unknown), TypeUid::Unknown);
        assert_eq!(TypeUid::from(ActivityId::Create), TypeUid::Create);
        assert_eq!(TypeUid::from(ActivityId::Other), TypeUid::Other);
    }

    #[test]
    fn ocsf_model_with_property_access_test() {
        let ocsf_model = generate_default_ocsf_model();
        assert_eq!(ocsf_model.severity_id, SeverityId::Unknown);
        assert_eq!(ocsf_model.activity_id, ActivityId::Read);
        assert_eq!(
            ocsf_model.metadata.product.vendor_name,
            "cedar-local-agent".to_string()
        );
        assert_eq!(
            ocsf_model.entity,
            generate_entity("user".to_string(), "alice".to_string())
        );
        assert!(ocsf_model.duration.is_none());
    }

    #[test]
    fn ocsf_test_default() {
        let ocsf_model = generate_default_ocsf_model();
        println!("{:?}", serde_json::to_string(&ocsf_model).unwrap());
        assert_eq!(ocsf_model.class_uid, 3004u64);
        assert_eq!(ocsf_model.category_uid, 3u8);
    }

    #[test]
    fn ocsf_test_serialization_and_rename() {
        let mut ocsf_model = generate_default_ocsf_model();
        ocsf_model.entity.entity_type = Some("Principal".to_string());
        let serialized = to_string(&ocsf_model).unwrap();
        let deserialized = from_str(&serialized).unwrap();
        assert_eq!(ocsf_model, deserialized);
        assert!(serialized.contains("\"type\":\"Principal\""));
        assert!(serialized.contains("\"activity_id\":2"));
    }

    #[test]
    fn ocsf_test_equality() {
        let ocsf_model = generate_default_ocsf_model();
        let ocsf_model_2 = generate_default_ocsf_model();
        assert_eq!(ocsf_model, ocsf_model_2);
    }

    #[test]
    fn ocsf_test_complex_type() {
        let mut ocsf_model = generate_default_ocsf_model();
        let mut enrichment_array: HashMap<String, Vec<String>> = HashMap::new();
        enrichment_array.insert(
            "key1".to_string(),
            vec!["value1.1".to_string(), "value1.2".to_string()],
        );

        ocsf_model.enrichments = Some(Vec::from([EnrichmentArrayBuilder::default()
            .name("data1")
            .value("value2")
            .data(enrichment_array)
            .build()
            .unwrap()]));
        ocsf_model.enrichments.as_ref().map_or_else(
            || {
                panic!("Enrichment Array is None");
            },
            |enrichments| {
                assert!(!enrichments[0].data.is_empty());
                assert_eq!(
                    enrichments[0].data["key1"],
                    vec!["value1.1".to_string(), "value1.2".to_string()]
                );
            },
        );

        let mut unmapped = Map::new();
        unmapped.insert("k1".to_string(), to_value("v1").unwrap());
        unmapped.insert("k2".to_string(), to_value("v2").unwrap());
        let unmapped_obj = to_value(unmapped).unwrap();
        ocsf_model.unmapped = Some(unmapped_obj.clone());
        assert!(ocsf_model.unmapped.is_some());
        assert_eq!(
            ocsf_model.unmapped.unwrap().to_string(),
            unmapped_obj.to_string()
        );
    }

    #[test]
    fn ocsf_validate_required_fields() {
        let model_with_no_activity_id = OpenCyberSecurityFrameworkBuilder::default()
            .type_uid(TypeUid::Read)
            .severity_id(SeverityId::Informational)
            .metadata(generate_metadata())
            .time(1_695_275_741_i64)
            .entity(generate_entity("user".to_string(), "alice".to_string()))
            .build();
        assert!(model_with_no_activity_id.is_err());
        assert!(matches!(
            model_with_no_activity_id,
            Err(UninitializedField(_))
        ));
    }

    #[test]
    fn ocsf_validate_activity_name() {
        let log_result = OpenCyberSecurityFrameworkBuilder::default()
            .type_uid(TypeUid::Read)
            .severity_id(SeverityId::Unknown)
            .metadata(generate_metadata())
            .time(1_695_275_741_i64)
            .entity(generate_entity("user".to_string(), "alice".to_string()))
            .activity_id(ActivityId::Read)
            .enrichments(generate_enrichment_array_vec(1))
            .activity_name(
                "this is an invalid activity name with \
            len larger than 35"
                    .to_string(),
            )
            .build();
        assert!(log_result.is_err());
        let _expected = generate_validation_error();
        assert!(matches!(log_result, _expected));
    }

    #[test]
    fn ocsf_validate_activity_name_enrichment_none() {
        let log_result = OpenCyberSecurityFrameworkBuilder::default()
            .type_uid(TypeUid::Read)
            .severity_id(SeverityId::Unknown)
            .metadata(generate_metadata())
            .time(1_695_275_741_i64)
            .entity(generate_entity("user".to_string(), "alice".to_string()))
            .activity_id(ActivityId::Read)
            .activity_name(
                "this is an invalid activity name with \
            len larger than 35"
                    .to_string(),
            )
            .build();
        assert!(log_result.is_err());
        let _expected = generate_validation_error();
        assert!(matches!(log_result, _expected));
    }

    #[test]
    fn ocsf_validate_activity_name_none() {
        let log_result = OpenCyberSecurityFrameworkBuilder::default()
            .type_uid(TypeUid::Read)
            .severity_id(SeverityId::Unknown)
            .metadata(generate_metadata())
            .time(1_695_275_741_i64)
            .entity(generate_entity("user".to_string(), "alice".to_string()))
            .activity_id(ActivityId::Read)
            .enrichments(generate_enrichment_array_vec(1))
            .activity_name(None)
            .build();
        assert!(log_result.is_ok());
    }

    #[test]
    fn ocsf_validate_activity_enrichments() {
        let log_result = OpenCyberSecurityFrameworkBuilder::default()
            .type_uid(TypeUid::Read)
            .severity_id(SeverityId::Unknown)
            .metadata(generate_metadata())
            .time(1_695_275_741_i64)
            .entity(generate_entity("user".to_string(), "alice".to_string()))
            .activity_id(ActivityId::Read)
            .enrichments(generate_enrichment_array_vec(10))
            .activity_name("safe-string".to_string())
            .build();
        assert!(log_result.is_err());
        let _expected = generate_validation_error();
        assert!(matches!(log_result, _expected));
    }

    /// This test proves that user request input is being redacted on `FieldSet::default()`
    #[test]
    fn validate_user_input_no_effect_on_log_size() {
        let response = generate_response(0, Decision::Allow);
        let fields = FieldSet::default();
        let authorizer_name = "cedar::local::agent::library";

        let request_json_1 = {
            let request = generate_mock_request("alice111");
            let entities = generate_custom_count_entities(100);

            let ocsf = OpenCyberSecurityFramework::create(
                &request,
                &response,
                &entities,
                &fields,
                authorizer_name,
            );

            serde_json::to_string(&ocsf.unwrap()).unwrap()
        };

        assert!(!request_json_1.contains("alice111"));
        assert!(!request_json_1.contains("bob"));

        let request_json_2 = {
            let request = generate_mock_request("alice");
            let entities = generate_custom_count_entities(50);
            let ocsf = OpenCyberSecurityFramework::create(
                &request,
                &response,
                &entities,
                &fields,
                authorizer_name,
            );

            serde_json::to_string(&ocsf.unwrap()).unwrap()
        };

        assert!(!request_json_2.contains("alice"));
        assert!(!request_json_2.contains("bob"));

        assert_eq!(request_json_1.len(), request_json_2.len());
    }

    #[test]
    fn ocsf_validate_activity_enrichments_activity_name_none() {
        let log_result = OpenCyberSecurityFrameworkBuilder::default()
            .type_uid(TypeUid::Read)
            .severity_id(SeverityId::Unknown)
            .metadata(generate_metadata())
            .time(1_695_275_741_i64)
            .entity(generate_entity("user".to_string(), "alice".to_string()))
            .activity_id(ActivityId::Read)
            .enrichments(generate_enrichment_array_vec(10))
            .build();
        let _expected = generate_validation_error();
        assert!(matches!(log_result, _expected));
    }

    #[test]
    fn ocsf_validate_activity_enrichments_none() {
        let log_result = OpenCyberSecurityFrameworkBuilder::default()
            .type_uid(TypeUid::Read)
            .severity_id(SeverityId::Unknown)
            .metadata(generate_metadata())
            .time(1_695_275_741_i64)
            .entity(generate_entity("user".to_string(), "alice".to_string()))
            .activity_id(ActivityId::Read)
            .enrichments(None)
            .activity_name("safe-string".to_string())
            .build();
        assert!(log_result.is_ok());
    }

    fn create_mock_request() -> Request {
        let principal = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("User").unwrap(),
            EntityId::from_str("Alice").unwrap(),
        );
        let action = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Action").unwrap(),
            EntityId::from_str("Read").unwrap(),
        );
        let resource = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Photo").unwrap(),
            EntityId::from_str("vacation.jpg").unwrap(),
        );
        Request::new(
            Some(principal),
            Some(action),
            Some(resource),
            Context::empty(),
            None,
        )
        .unwrap()
    }

    fn create_mock_entities() -> Entities {
        let entities_data = r#"
	         [
	           {
	             "uid": { "type": "User", "id": "Alice" },
	             "attrs": {},
	             "parents": []
	           },
	           {
	             "uid": { "type": "User", "id": "Bob"},
	             "attrs" : {},
	             "parents": []
	           }
	         ]"#;
        Entities::from_json_str(entities_data, None).unwrap()
    }

    #[test]
    fn filter_request_default_field_set() {
        let request = create_mock_request();
        let entities = create_mock_entities();
        let field_set = FieldSetBuilder::default().build().unwrap();
        let filtered_request = filter_request(&request, &entities, &field_set);

        assert_eq!(filtered_request.principal, EntityComponent::None);
        assert_eq!(filtered_request.action, EntityComponent::None);
        assert_eq!(filtered_request.resource, EntityComponent::None);
        assert!(filtered_request.context.is_none());
        assert!(filtered_request.entities.is_none());
    }

    #[test]
    fn filter_request_all_fields_set() {
        let request = create_mock_request();
        let entities = create_mock_entities();
        let field_set = FieldSetBuilder::default()
            .principal(true)
            .action(true)
            .resource(true)
            .context(true)
            .entities(FieldLevel::All)
            .build()
            .unwrap();
        let filtered_request = filter_request(&request, &entities, &field_set);

        assert!(matches!(
            filtered_request.principal,
            EntityComponent::Concrete(_)
        ));
        assert!(matches!(
            filtered_request.action,
            EntityComponent::Concrete(_)
        ));
        assert!(matches!(
            filtered_request.resource,
            EntityComponent::Concrete(_)
        ));
        assert!(filtered_request.context.is_some());
        assert!(filtered_request.entities.is_some());
    }

    #[test]
    fn filter_request_custom_field_set() {
        let request = create_mock_request();
        let entities = create_mock_entities();
        let filter_fn = |_entities: &Entities| -> Entities { Entities::empty() };
        let field_set = FieldSetBuilder::default()
            .principal(true)
            .context(true)
            .entities(FieldLevel::Custom(filter_fn))
            .build()
            .unwrap();

        let filtered_request = filter_request(&request, &entities, &field_set);

        assert!(matches!(
            filtered_request.principal,
            EntityComponent::Concrete(_)
        ));
        assert!(matches!(filtered_request.action, EntityComponent::None));
        assert!(matches!(filtered_request.resource, EntityComponent::None));

        assert_eq!(filtered_request.context, Some(request.to_string()));
        assert_eq!(filtered_request.entities, Some(Entities::empty()));
    }

    #[test]
    fn ocsf_error_log() {
        let ocsf = OpenCyberSecurityFramework::error(
            "Failed to create error".to_string(),
            "some_authorizer".to_string(),
        );

        assert_eq!(ocsf.type_uid, TypeUid::Other);
        assert_eq!(ocsf.severity_id, SeverityId::Other);
        assert_eq!(ocsf.activity_id, ActivityId::Other);
        assert_eq!(
            ocsf.entity,
            ManagedEntityBuilder::default()
                .name("N/A".to_string())
                .build()
                .unwrap()
        );
        assert_eq!(ocsf.message.unwrap(), "Failed to create error".to_string());
        assert_eq!(
            ocsf.metadata,
            MetaDataBuilder::default()
                .version(OCSF_SCHEMA_VERSION)
                .product(
                    ProductBuilder::default()
                        .vendor_name(VENDOR_NAME)
                        .name("some_authorizer".to_string())
                        .build()
                        .unwrap()
                )
                .build()
                .unwrap()
        );
    }

    #[test]
    fn display_entity_component_concrete() {
        let component = EntityComponent::Concrete(EntityUid::from_str("Action::\"test\"").unwrap());
        assert_eq!("test", component.to_string());
    }

    #[test]
    fn display_entity_component_unknown() {
        let component = EntityComponent::Unknown;
        assert_eq!("partial evaluation", component.to_string());
    }

    #[test]
    fn check_partial_evaluation_error() {
        let component = EntityComponent::Unknown;
        assert!(component.get_id().is_err());
    }
}
