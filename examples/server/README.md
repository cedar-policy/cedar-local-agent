# Cedar Local Agent for Rust server example

## Purpose

This is a simple example of how to start a Rust server with Cedar Local Agent Authorizer using cedar-local-agent, [tower](https://docs.rs/tower/latest/tower/index.html), and [hyper](https://docs.rs/hyper/latest/hyper/index.html).

## Code example

[Server](src)

## Start Server

To start the server, use the following command:

```bash
cargo run
```

The server will start on http://127.0.0.1:3000.

## Writing a query against the sever

Sample request

```
{
   "principal": {
        "uid": {
             "__entity": {
                 "type": "User",
                 "id": "Mike"
             }
        }
   },
   "action": {
        "uid": {
             "__entity": {
                 "type": "Action",
                 "id": "read"
             }
        }
   },
   "resource": {
        "uid": {
             "__entity": {
                 "type": "Box",
                 "id": "2"
             }
        }
   }
}
```

Sample curl:

```
// Expects 200 OK
cat request_allow.json | base64 | xargs sh -c 'curl -vvv localhost:3003 -H "Authorization: $1"' sh

// Expect 401 Unauthorized
cat request_deny.json | base64 | xargs sh -c 'curl -vvv localhost:3003 -H "Authorization: $1"' sh
```

<br>
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: Apache-2.0
