mod entities;
mod policy;
mod utils;

use crate::entities::generate_entities;
use crate::policy::generate_policy_set;
use cedar_policy::{Entities, EntityTypeName, Policy, PolicySet};
use std::fs::File;
use std::str::FromStr;
use std::{env, fs};

pub fn policy_set_to_string(policy_set: PolicySet) -> String {
    let mut policy_set_string = String::new();

    for policy in policy_set.policies() {
        policy_set_string.push_str(policy.to_string().as_str());
    }

    policy_set_string
}

fn generate_request() -> Policy {
    let policy_str = r#"
     permit(
       principal == Principal::"request",
       action == Action::"request",
       resource == Resource::"request"
     );"#;

    Policy::parse(None, policy_str).unwrap()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        panic!("File name missing! Use data_gen <file_name> <num_policies>");
    }
    let file_name = &args[1];
    let num_policies: u32 = String::from(&args[2]).parse::<u32>().unwrap() - 1;

    let principals = generate_entities(32, EntityTypeName::from_str("Principal").unwrap());
    let actions = generate_entities(32, EntityTypeName::from_str("Action").unwrap());
    let resources = generate_entities(32, EntityTypeName::from_str("Resource").unwrap());
    let mut policy_set = generate_policy_set(
        num_policies,
        principals.clone(),
        actions.clone(),
        resources.clone(),
    );

    policy_set.add(generate_request()).unwrap();

    let policy_set_string = policy_set_to_string(policy_set);
    fs::write(format!("{}.cedar", file_name), policy_set_string.clone()).unwrap();

    let entities = Entities::from_entities(
        principals
            .iter()
            .cloned()
            .chain(actions.iter().cloned())
            .chain(resources.iter().cloned()),
        None,
    )
    .unwrap();
    let entities_file = File::create(format!("{}.entities.json", file_name)).unwrap();
    entities.write_to_json(entities_file).unwrap();
}
