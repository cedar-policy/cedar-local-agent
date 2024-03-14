# Cedar Local Agent

This crate is experimental.

The `cedar-local-agent` crate provides customers a useful foundation for creating asynchronous authorizers that
can handle two different operational modes:

1. The authorizer is **able** to cache all of your application’s policies and entity data while evaluating a request
2. The authorizer is **unable** to cache all of your application's policies and entity data while evaluating a request

The `cedar-local-agent` crate provides a [`simple::Authorizer`](./src/public/simple.rs) which can be built with option (1) or (2). The
[`simple::Authorizer`](./src/public/simple.rs) is constructed using policy and entity providers. These providers can be
implemented by customers.

`cedar-local-agent` provides sample implementations of providers that implement option (1). A file system policy set provider:
[`file::PolicySetProvider`](./src/public/file/policy_set_provider.rs), and an entity provider:
[`file::EntityProvider`](./src/public/file/entity_provider.rs).

For more information about the Cedar language/project, please take a look
at [cedarpolicy.com](https://www.cedarpolicy.com).

## Usage

Cedar Local Agent can be used in your application via the `cedar-local-agent` crate.

Add `cedar-local-agent` as a dependency in your `Cargo.toml` file. For example:

```toml
[dependencies]
cedar-local-agent = "2"
```

## Quick Start

Build a local authorizer that evaluates authorization decisions using a locally stored
policy set, entity store and schema.

Policy data: [`tests/data/sweets.cedar`](./tests/data/sweets.cedar)

Entity data: [`tests/data/sweets.entities.json`](./tests/data/sweets.entities.json)

Schema: [`tests/data/sweets.schema.cedar.json`](./tests/data/sweets.schema.cedar.json)

Build a policy set:

```rust
let policy_set_provider = PolicySetProvider::new(
    policy_set_provider::ConfigBuilder::default()
        .policy_set_path("tests/data/sweets.cedar")
        .build()
        .unwrap(),
)
.unwrap();
```

Build an entity provider:

```rust
let entity_provider = EntityProvider::new(
    entity_provider::ConfigBuilder::default()
        .entities_path("tests/data/sweets.entities.json")
        .schema_path("tests/data/sweets.schema.cedar.json")
        .build()
        .unwrap(),
)
.unwrap();
```

Build the authorizer:

```rust
let authorizer: Authorizer<PolicySetProvider, EntityProvider> = Authorizer::new(
    AuthorizerConfigBuilder::default()
        .entity_provider(Arc::new(entity_provider))
        .policy_set_provider(Arc::new(policy_set_provider))
        .build()
        .unwrap(),
);
```

Evaluate a decision:

```rust
assert_eq!(
    authorizer
        .is_authorized(&Request::new(
            Some(format!("User::\"Cedar\"").parse().unwrap()),
            Some(format!("Action::\"read\"").parse().unwrap()),
            Some(format!("Box::\"3\"").parse().unwrap()),
            Context::empty(),
        ), &Entities::empty())
        .await
        .unwrap()
        .decision(),
    Decision::Deny
)
```

## [`simple::Authorizer`](./src/public/simple.rs) `is_authorized` API Semantics

The [`simple::Authorizer`](./src/public/simple.rs) `is_authorized` API takes a
[`Cedar request`](https://github.com/cedar-policy/cedar/tree/main/cedar-policy)
and [`Cedar entities`](https://github.com/cedar-policy/cedar/tree/main/cedar-policy) within the API.

```rust
pub async fn is_authorized(
    &self,
    request: &Request,
    entities: &Entities,
) -> Result<Response, AuthorizerError> { ... }
```

For scenarios where the same entity identifier, `EID`, is passed as input and returned by an `EntityProvider`, the input is
considered the last value. This API favors last-value-wins semantics.
This behavior is subject to change pending [`RFC-0020`](https://github.com/cedar-policy/rfcs/blob/main/text/0020-unique-record-keys.md).

## Updating [`file::PolicySetProvider`](./src/public/file/policy_set_provider.rs) or [`file::EntityProvider`](./src/public/file/entity_provider.rs) data

The [`file::PolicySetProvider`](./src/public/file/policy_set_provider.rs) and [`file::EntityProvider`](./src/public/file/entity_provider.rs)
gather data when initialized and cache it in memory. No data is read from disk during an authorization decision.

Policy and entity data can be mutated on disk after the initialization of an authorizer. To account for this, functionality
is provided which will refresh policy and entity data tangential to an authorization decision.
To accomplish this, a minimum of two additional threads are required, for a total of three threads.

1. The main thread handles `is_authorized` calls
2. The signaler thread notifies receivers of required updates
3. The receiver thread listens for updates

[`Channels`](https://doc.rust-lang.org/rust-by-example/std_misc/channels.html) are used to communicate between the signaler thread and
the receiver thread. There are two provided functions for creating signaler threads. Both return a signaler thread and a
[`tokio::broadcast::receiver`](https://docs.rs/tokio/latest/tokio/sync/broadcast/struct.Receiver.html) as an output.

1. [`clock_ticker_task`](./src/public/events/core.rs) periodically wakes up and signals based on a clock duration
2. [`file_inspector_task`](./src/public/events/core.rs) periodically wakes up and checks for differences in a file
   using a collision resistant hashing function (SHA256) and notifies on modifications

Warning: It is important to be careful when selecting the refresh rate of the signaler which triggers a policy refresh.
We have set up a `RefreshRate` enum which gives several options of RefreshRates of at least 15 seconds.
This is fast enough for most applications but slow enough to be very unlikely to trigger any sort of throttling or performance impact on most policy set sources.


Receivers are required to be passed to a new separate thread to listen and respond to events.
The [`update_provider_data_task`](./src/public/events/receive.rs) handles receiving these signals in the form of an
[`Event`](./src/public/events/mod.rs). Messages are handled one message at a time. The receiver thread blocks until
it has successfully or unsuccessfully updated the data for the provider.

Sample usage of updating a policy set provider's data every fifteen seconds:

```rust
let (clock_ticker_signal_thread, receiver) = clock_ticker_task(RefreshRate::FifteenSeconds);

let policy_set_provider = Arc::new(PolicySetProvider::new(
    policy_set_provider::ConfigBuilder::default()
        .policy_set_path("tests/data/sweets.cedar")
        .build()
        .unwrap(),
)
.unwrap());

let update_provider_thread = update_provider_data_task(policy_set_provider.clone(), receiver);
```

Note: these background threads must remain in scope for the life of your application. If there is an issue updating
in a background thread it will produce an `error!()` message but will not cause the application to crash.

This means that if for any reason, the agent cannot update its policy set due to an error, the agent will continue running with the stale policy set and will log an error.
Since the agent will log `error!()`'s, it is possible to configure log-based alarms so that these failures can be caught quickly, but that is outside the scope of this README.

## Tracing

This crate emits trace data [`tracing`](https://docs.rs/tracing/latest/tracing/) and can be integrated
into standard tracing implementations.

## Authorization Logging

Authorization logs are designed to power detection and response capabilities. Sample capabilities can be found
under the [`Mitre D3fend matrix`](https://d3fend.mitre.org/),
for example [`User Behavioral Analysis`](https://d3fend.mitre.org/technique/d3f:UserBehaviorAnalysis/).

The authorizer's provided emit authorization events as [`tracing events`](https://docs.rs/tracing/latest/tracing/struct.Event.html).
Authorization events are included in tracing [`spans`](https://docs.rs/tracing/latest/tracing/span/index.html).
Authorization events are default formatted using [`Open Cyber Security Format`](https://github.com/ocsf).
Authorization events can optionally be filtered, formatted and routed directly to an authorization log. See example:

```rust
// Dependencies must be included in the `Cargo.toml` file of the application
// tracing, tracing-appender, tracing-subscriber

let authorization_roller = tracing_appender::rolling::minutely("logs", "authorization.log");
let (authorization_non_blocking, _guard) = tracing_appender::non_blocking(authorization_roller);
let authorization_log_layer = tracing_subscriber::fmt::layer()
    .event_format(AuthorizerFormatter(AuthorizerTarget::Simple))
    .with_writer(authorization_non_blocking);
tracing_subscriber::registry()
    .with(authorization_log_layer)
    .try_init()
    .expect("Logging Failed to Start, Exiting.");
```

To filter authorization event logs, provide a log config to the authorizer with a `FieldSet` which includes the fields that are to be logged. By default if not explicitly configured, no fields will be logged.

Sample usage of logging everything within the authorization request. **Note**: Logging everything is insecure; please see [Secure Logging Configuration](#secure-logging-configuration). 

```rust
let log_config =
    log::ConfigBuilder::default()
        .field_set(log::FieldSetBuilder::default()
            .principal(true)
            .action(true)
            .resource(true)
            .context(true)
            .entities(log::FieldLevel::All)
            .build()
            .unwrap())
    .build()
    .unwrap();

let authorizer: Authorizer<PolicySetProvider, EntityProvider> = Authorizer::new(
    AuthorizerConfigBuilder::default()
        .entity_provider(...)
        .policy_set_provider(...)
        .log_config(log_config)
        .build()
        .unwrap(),
);
```

Note: ``Authorizer`` ``log_config`` ``FieldSet::entities `` refers to the Cedar entities. 
There is also an [OCSF](https://github.com/ocsf) field called [``entity``](https://github.com/cedar-policy/cedar-local-agent/blob/main/src/public/log/schema.rs#L86) which refers to the principal entity that is sending the request.

This means that when ``Authorizer`` ``log_config`` ``FieldSet::entities`` is set to ``FieldLevel::None``, the OCSF entity will still be logged. 
This is not a bug and is expected behaviour.

For more examples of how to set up the authorization logging, see our [usage examples](https://github.com/cedar-policy/cedar-local-agent/tree/main/examples/tracing/authorization_log)

### Secure Logging Configuration:

Using a `log::FieldSet` configuration that sets any cedar-related field (principal, action, resource, context, and entities) to `true` will result in that field being logged. 
These fields could contain sensitive information and should be exposed with caution. Additionally, the cedar language has no current limit on field sizes within a [`Request`](https://docs.rs/cedar-policy/2.4.0/cedar_policy/struct.Request.html). 
A large request with verbose logging can result in more disk i/o to occur. This disk i/o could negatively impact the performance of the application.

For a safe config, create a default `log::FieldSet` with `log::FieldSetBuilder::default().build().unwrap()`. 
This option will redact user input like so: 

`"entity":{"data":{"Parents":[]},"name":"Sensitive<REDACTED>","type":"Sensitive<REDACTED>"}`

### Note:

Cedar does not at this time support extracting the `Context` from the `Request` struct since it is private, therefore it is extracted using `request.to_string()`. This is not ideal as this logs the entire request (Principal, Action, Resource, Context) instead of just the context.

In particular this brings two quirks:

- If the `FieldSet` has principal and context set to true, then the resulting log will include the principal twice.
- If the `FieldSet` has principal set to false and context set to true, then the resulting log will include principal anyway since it is included in the `request.to_string()` call required to extract the context.

The above are not specific to principal and also occur with action and resource. A cedar github issue has been created to add a getter for the context on the cedar Request struct that will fix this: https://github.com/cedar-policy/cedar/issues/363

## Example application

This project is based on a fictitious application that allows users to manage sweet boxes. There are two entities:

1. Box (Resource)
2. User (Principal)

There are two user entities:

1. Eric
2. Mike

There are ten resources, `Box`. Each box has an entity identifier (id) that ranges
between the numbers 1-10. Each `Box` has one attribute `owner`. The owners of each `Box` are defined in
the [`tests/data/sweets.entities.json`](./tests/data/sweets.entities.json) file,
this file represents the complete database of information for this application.

The actions that `Users` can perform on each `Box` are defined in the schema file:
[`tests/data/sweets.schema.cedar.json`](./tests/data/sweets.schema.cedar.json). To summarize, each `User`
can perform one of the following actions `read`, `update` or `delete` on a `Box` resource.

A policy is a statement that declares which `Users` are explicitly permitted, or explicitly forbidden to perform an
action on a resource, `Box`. Here is a sample policy:

```
@id("owner-policy")
permit(principal, action, resource)
when { principal == resource.owner };
```

Refer to [`tests/data/sweets.cedar`](./tests/data/sweets.cedar) for the full details of these policies.
This file represents all policies for this application.

Given the `schema`, `entities` and `policy_set` the application can use the `Authorizer` as provided in the usage above.
Here is a sample request and expected outcome:

```rust
 assert_eq!(
     authorizer
         .is_authorized(&Request::new(
             Some(format!("User::\"Mike\"").parse().unwrap()),
             Some(format!("Action::\"read\"").parse().unwrap()),
             Some(format!("Box::\"3\"").parse().unwrap()),
             Context::empty(),
         ), &Entities::empty())
         .await
         .unwrap()
         .decision(),
     Decision::Deny
 );
 assert_eq!(
     authorizer
         .is_authorized(&Request::new(
             Some(format!("User::\"Mike\"").parse().unwrap()),
             Some(format!("Action::\"read\"").parse().unwrap()),
             Some(format!("Box::\"2\"").parse().unwrap()),
             Context::empty(),
         ), &Entities::empty())
         .await
         .unwrap()
         .decision(),
     Decision::Allow
 );
```

Feel free to refer to this sample application within the integration test located here: [`tests/lib.rs`](./tests/lib.rs).

## General Security Notes

The following is a high level description of some security concerns to keep in mind when using the `cedar-local-agent`
to enable local evaluation of Cedar policies stored on a local file system.

### Trusted Computing Environment

The `cedar-local-agent` is a mere library that customers can wrap in say an HTTP server and deploy onto a fleet of hosts.
It is, therefore, left to users to take any and all necessary precautions to ensure those security concerns beyond what
the `cedar-local-agent` is capable of enforcing are met. This includes:

1. Filesystem permissions for on-disk Policy Stores should be limited to least-privilege, see [Limiting Access to Local Data Files](#limiting-access-to-local-data-files).
2. Filesystem permissions for on-disk locations of OCSF logs follow least-privilege permissions, see [OCSF Log directory permissions](#ocsf-log-directory-permissions).
3. The `cedar-local-agent` is configured securely, see [Quick Start](#quick-start) and [Updating `file::PolicySetProvider` or `file::EntityProvider` data](#updating-filepolicysetprovider-or-fileentityprovider-data) for configuration best practices.
4. Validating the size of files read and requests made to `is_authorized` to prevent potential denial of service.

### Limiting Access to Local Data Files

The local authorizer provided in this crate only needs **read** access to locally stored policy set, entity store and
schema files.

Write access to local data files (policies, entities and schema) should be restricted only to users that really
need to make changes to these files, for example, to add new entities and remove old policies.

In the case where there are no restrictions to access local data files, a malicious Operating System (OS) user can add or
remove policies, modify entities attributes, make slight changes that are hard to identify, or even change the policies
to deny all actions. To illustrate this possibility, consider a cedar file with the following cedar policies from the
[Example Application](## Example application):

```
@id("mike-edit-box-1")
permit (
    principal == User::"Mike",
    action == Action::"update",
    resource == Box::"1"
);

@id("eric-view-box-9")
permit (
    principal == User::"Eric",
    action == Action::"read",
    resource == Box::"9"
);
```

In this example, principal "Mike" is allowed to perform "update" on resource box "1" while principal "Eric" is allowed to
perform "read" on resource box "9". Now, consider a malicious OS user adding the statement below to the same policies file.

```
@id("ill-intentioned-policy")
forbid(principal, action, resource);
```

In the next policies file refresh cycle, the [`file::PolicySetProvider`](./src/public/file/policy_set_provider.rs) will refresh policies file content to memory,
and the local authorizer will deny any action from any principal.

#### How to avoid this problem from happening?

In order to prevent this kind of security issue, you must restrict read access to the data files, and more important,
restrict write access to these files. Only users or groups that really need to write changes to policies,
or entities should be allowed to do so (for example, another agent that fetches policies from an internal application).

For one example on how to avoid this problem, say you have the following folder structure for a local-agent built with
`cedar-local-agent` crate.

```
authz-agent/
  |- authz_daemon (executable)

authz-local-data/
  |- policies.cedar
  |- entities.json
  |- schema.json
```

Now suppose you have an OS user to execute the "authz_daemon" called "authz-daemon" from user group "authz-ops".
And you have a user called "authz-ops-admin" from the same user group "authz-ops" that will be able to update data files.

Then, make "authz-ops-admin" the owner of **authz-local-data** folder with:

```bash
$ chown -R authz-ops-admin:authz-ops authz-local-data
```

And make "authz-daemon" user the owner of **authz-agent** folder with:

```bash
$ chown -R authz-daemon:authz-ops authz-agent
```

Finally, make **authz-local-data** readable by everyone and writable by the owner only:

```bash
$ chmod u=rwx,go=r authz-local-data
```

### OCSF Log directory permissions


The local authorizer provided in this crate will require **read** and **write** access to the directory where it will write OCFS logs to.

Suppose we have the following directory structure:

```
authz-agent/
  |- authz_daemon (executable)

ocsf-log-dir/
  |- authorization.log.2023-11-15-21-02
  ...
```

Now suppose you have an OS user to execute the **authz_daemon** called **authz-daemon** which should be in a group called "log-reader".

And make **authz-daemon** user the owner of  **ocsf-log-dir** folder with:

```bash
$ chown -R authz-daemon:log-reader ocsf-log-dir
```

We will now make **ocsf-log-dir** readable and writable by the owner but not writable to anyone else.
We allow anyone in the **log-reader** group to read the contents of the folder but not write to it.

```bash
$ chmod u=wrx,g=rx,o= ocsf-log-dir
```

NOTE: We need to allow **execute** permissions in order to access files in the directory.

Any agent that needs to access the logs, such as the [AWS Cloudwatch Agent](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Install-CloudWatch-Agent.html) should run as a user in the log-reader group so that they will have the proper access (see [documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Agent-common-scenarios.html) for how to configure the Cloudwatch Agent to run as a certain user).

## Getting Help

- [GitHub issues](https://github.com/cedar-policy/cedar-local-agent/issues)
- [Cedar documentation](https://docs.cedarpolicy.com/)
- [Usage examples](examples)

## License

This project is licensed under the Apache-2.0 License.
