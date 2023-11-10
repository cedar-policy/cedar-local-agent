# Cedar Local Agent for Rust tracing example

## Purpose
This is documentation for the developer to set up tracing at executable to initialize a subscriber for logging tracing data.<br>

## Logging with the Cedar Local Agent
The Cedar Local Agent uses [tracing](https://docs.rs/tracing/latest/tracing/) framework for logging.
<br>

To see structured logging information which tracks spans and events. We recommend using tracing-specific libraries, such as [tracing_subscriber](https://tracing.rs/tracing_subscriber/index.html) or [tracing_appender](https://tracing.rs/tracing_appender/index.html).

Add the tracing library to your Cargo.toml file:
```
tracing = "0.1"
tracing-core = "0.1"
tracing-subscriber = "0.3"
```

Then, initialize the logger in the `main` function before start your server.
```
// A new log file in the format of some_directory/log_file_name_prefix.yyyy-MM-dd-HH-mm will be created minutely (once per minute)
    let roller = tracing_appender::rolling::minutely("logs", "log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(roller);

    let layer = tracing_subscriber::fmt::layer().with_writer(non_blocking);

    tracing_subscriber::registry()
        .with(layer)
        .try_init()
        .expect("Logging Failed to Start, Exiting.");
```

To apply the `fmt` layer for improved log formatting, you can set up [tracing_subscriber::fmt::Layer](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/fmt/struct.Layer.html) and [tracing_subscriber::filter](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/index.html)

For example if want `INFO` level application log in `cedar_local_agent` using json format:
```
    let filter =
        tracing_subscriber::filter::Targets::new().with_target("cedar_local_agent", Level::INFO);

    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(non_blocking)
        .with_filter(filter);

    tracing_subscriber::registry()
        .with(layer)
        .try_init()
        .expect("Logging Failed to Start, Exiting.");
```


<br>
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved. SPDX-License-Identifier: Apache-2.0