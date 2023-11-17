# Cedar Local Agent for Rust tracing example

## Purpose

The Cedar Local Agent uses [tracing](https://docs.rs/tracing/latest/tracing/) framework for logging.

This example demonstrates how to perform tracing logging using the Cedar Local Agent for Rust.

## Code example

[Application Log Example](application_log)

[Authorization Log Example](authorization_log)

To generate the tracing log records, use the following command:

## Run the code

```bash
cargo run
```

The log records will be generated at "output/tracing_example_logs"

### Application log record example
```
{"timestamp":"...","level":"INFO","fields":{"message":"Initialized Entity Provider"},"target":"cedar_local_agent::public::simple","span"...}
{"timestamp":"...","level":"INFO","fields":{"message":"Initialized Policy Set Provider"},...}
{"timestamp":"...","level":"INFO","fields":{"message":"Initialize Simple Authorizer: authorizer_id=...},...}
...
{"timestamp":"...","level":"INFO","fields":{"message":"Generated OCSF log record."},...}
{"timestamp":"...","level":"INFO","fields":{"message":"Is_authorized completed: response_decision=Deny"},...}
```

### Authorization log record example
```
{"activity_name":"Sensitive<REDACTED>","activity_id":99,"category_name":"Identity & Access Management","category_uid":3,"class_name":"Entity Management","class_uid":3004,"entity":{"data":{"Parents":[]},"name":"Sensitive<REDACTED>","type":"Sensitive<REDACTED>"},"entity_result":{"data":{"Parents":[]},"name":"Sensitive<REDACTED>","type":"Sensitive<REDACTED>"},"time":1700085292,"message":"Principal Sensitive<REDACTED> performed action Sensitive<REDACTED> on Sensitive<REDACTED>, the decision is Deny determined by policy id [] and errors []","metadata":{"version":"1.0.0","product":{"vendor_name":"cedar::simple::authorizer","name":"cedar::simple::authorizer","lang":"en"},"log_provider":"cedar::simple::authorizer","processed_time":0,"logged_time":1700085292,"log_version":"1.0.0"},"severity":"Informational","severity_id":1,"status":"Success","status_code":"Deny","status_detail":"","status_id":1,"timezone_offset":-420,"type_uid":300499,"type_name":"Other","unmapped":{"context":"Sensitive<REDACTED>","determined_policies":[],"evaluation_errors":[],"action_entity_details":{"data":{"Parents":[]},"name":"Sensitive<REDACTED>","type":"Sensitive<REDACTED>"}}}
```

<br>
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: Apache-2.0
