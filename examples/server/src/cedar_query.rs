use std::fmt::Debug;
use std::str::FromStr;
use std::string::FromUtf8Error;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use cedar_policy::{Context, EntityId, EntityTypeName, EntityUid, Request};
use cedar_policy_core::parser::err::ParseErrors;

#[derive(Debug, Error)]
pub enum EvaluationError {
    #[error("Invalid Request, {0}")]
    Request(#[source] ParseErrors),
    #[error("Invalid Request, {0}")]
    Json(#[source] serde_json::Error),
    #[error("Invalid Request, {0}")]
    Utf8(#[source] FromUtf8Error),
}

impl From<ParseErrors> for EvaluationError {
    fn from(value: ParseErrors) -> Self {
        EvaluationError::Request(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CedarQuery {
    #[serde(rename = "principal")]
    pub principal: EntityUuid,
    #[serde(rename = "resource")]
    pub resource: EntityUuid,
    #[serde(rename = "action")]
    pub action: EntityUuid,
    #[serde(rename = "context")]
    pub context: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntityUuid {
    #[serde(rename = "uid")]
    pub uid: EntityExtension,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntityExtension {
    #[serde(rename = "__entity")]
    pub entity: Entity,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entity {
    #[serde(rename = "type")]
    pub entity_type: String,
    #[serde(rename = "id")]
    pub entity_id: String,
}

impl TryFrom<CedarQuery> for Request {
    type Error = EvaluationError;

    fn try_from(q: CedarQuery) -> Result<Self, Self::Error> {
        let principal = Some(EntityUid::from_type_name_and_id(
            EntityTypeName::from_str(q.principal.uid.entity.entity_type.as_str())?,
            EntityId::from_str(q.principal.uid.entity.entity_id.as_str())?,
        ));
        let action = Some(EntityUid::from_type_name_and_id(
            EntityTypeName::from_str(q.action.uid.entity.entity_type.as_str())?,
            EntityId::from_str(q.action.uid.entity.entity_id.as_str())?,
        ));
        let resource = Some(EntityUid::from_type_name_and_id(
            EntityTypeName::from_str(q.resource.uid.entity.entity_type.as_str())?,
            EntityId::from_str(q.resource.uid.entity.entity_id.as_str())?,
        ));
        Ok(Request::new(principal, action, resource, Context::empty()))
    }
}
