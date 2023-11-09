#!/bin/sh

rustup update stable && rustup default stable && \
cargo fmt --all --check && \
RUSTFLAGS="-D warnings -F unsafe-code" cargo build --verbose && \
cargo doc --all-features --no-deps && \
RUSTFLAGS="-D warnings" cargo clippy --all-features --tests && \
cargo test --verbose && \
# cargo test --verbose --features integration-tests && \
cargo test --verbose --no-default-features && \
cargo test --verbose -- --ignored && \
cargo bench --no-run && \
cargo audit --deny warnings && \
cargo deny check
