use super::utils::{random_string, ALPHA};
use cedar_policy::{Entities, Entity, EntityId, EntityTypeName, EntityUid};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

const FIELD_LEN: u32 = 12;
const FIELD_CHARSET: &str = ALPHA;

fn generate_entity_uid(entity_type: EntityTypeName) -> EntityUid {
    let eid = EntityId::from_str(random_string(FIELD_LEN, FIELD_CHARSET).as_str()).unwrap();

    EntityUid::from_type_name_and_id(entity_type, eid)
}

pub fn generate_entities(num_entities: u32, entity_type: EntityTypeName) -> Entities {
    let mut entities: Vec<Entity> = Vec::new();
    for _ in 0..num_entities {
        entities.push(
            Entity::new(
                generate_entity_uid(entity_type.clone()),
                HashMap::new(),
                HashSet::new(),
            )
            .unwrap(),
        );
    }

    Entities::from_entities(entities, None).unwrap()
}
