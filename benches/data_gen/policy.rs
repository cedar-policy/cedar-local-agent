use crate::utils::{random_string, ALPHA};
use cedar_policy::{Entities, Entity, Policy, PolicySet};
use rand::seq::IteratorRandom;
use rand::Rng;
use serde::ser::{SerializeStruct, Serializer};
use serde::Serialize;

const POLICY_ID_LEN: u32 = 10;
const POLICY_ID_CHARSET: &str = ALPHA;

#[derive(Serialize, PartialEq)]
struct EntityUidRepr {
    #[serde(rename = "type")]
    type_name: String,
    id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum Effect {
    Permit,
    Forbid,
}

#[derive(PartialEq)]
enum Operation {
    All,
    Eq(EntityUidRepr),
}

#[derive(Serialize)]
struct ConditionRepr {}

#[derive(Serialize)]
struct PolicyRepr {
    effect: Effect,
    principal: Operation,
    action: Operation,
    resource: Operation,
    conditions: Vec<ConditionRepr>,
}

impl Serialize for Operation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state;
        match self {
            Operation::All => {
                state = serializer.serialize_struct("NA", 1)?;
                state.serialize_field("op", "All")?;
            }
            Operation::Eq(val) => {
                state = serializer.serialize_struct("NA", 2)?;
                state.serialize_field("op", "==")?;
                state.serialize_field("entity", val)?;
            }
        }

        state.end()
    }
}

impl From<Entity> for EntityUidRepr {
    fn from(value: Entity) -> Self {
        EntityUidRepr {
            type_name: value.uid().type_name().to_string(),
            id: value.uid().to_string(),
        }
    }
}

fn random_effect() -> Effect {
    let mut rng = rand::rng();
    let rand = rng.random_range(0..2);

    if rand == 0 {
        Effect::Permit
    } else {
        Effect::Forbid
    }
}

fn random_operation(entity_uid: EntityUidRepr) -> Operation {
    let mut rng = rand::rng();
    let rand = rng.random_range(0..2);

    if rand == 0 {
        Operation::All
    } else {
        Operation::Eq(entity_uid)
    }
}

fn random_entity(entities: &Entities) -> Entity {
    let mut rng = rand::rng();

    entities.iter().choose(&mut rng).unwrap().clone()
}

fn generate_policy(principal: Entity, action: Entity, resource: Entity) -> PolicyRepr {
    let policy = PolicyRepr {
        effect: random_effect(),
        principal: random_operation(principal.clone().into()),
        action: random_operation(action.clone().into()),
        resource: random_operation(resource.clone().into()),
        conditions: Vec::new(),
    };

    if policy.principal == Operation::All
        && policy.action == Operation::All
        && policy.resource == Operation::All
    {
        generate_policy(principal, action, resource)
    } else {
        policy
    }
}

pub fn generate_policy_set(
    num_policies: u32,
    principals: Entities,
    actions: Entities,
    resources: Entities,
) -> PolicySet {
    let mut policy_set = PolicySet::new();

    for _ in 0..num_policies {
        let policy_repr = generate_policy(
            random_entity(&principals),
            random_entity(&actions),
            random_entity(&resources),
        );
        let policy_json = serde_json::to_value(&policy_repr).unwrap();
        let policy = Policy::from_json(
            Some(
                random_string(POLICY_ID_LEN, POLICY_ID_CHARSET)
                    .parse()
                    .unwrap(),
            ),
            policy_json,
        )
        .unwrap();

        policy_set.add(policy).unwrap();
    }

    policy_set
}
