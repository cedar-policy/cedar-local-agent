#!/bin/sh

rustup update stable && rustup default stable && \

echo ">>>> cargo fmt --all --check" && \
cargo fmt --all --check && \

echo ">>>> cargo build --verbose" && \
RUSTFLAGS="-D warnings -F unsafe-code" cargo build --verbose && \

echo ">>>> cargo doc --all-features --no-deps" && \
cargo doc --all-features --no-deps && \

echo ">>>> cargo clippy --all-features --tests" && \
RUSTFLAGS="-D warnings" cargo clippy --all-features --tests && \

echo ">>>> cargo test --verbose" && \
cargo test --verbose && \

# cargo test --verbose --features integration-tests && \

echo ">>>> cargo test --verbose --no-default-features" && \
cargo test --verbose --no-default-features && \

echo ">>>> cargo test --verbose -- --ignored" && \
cargo test --verbose -- --ignored && \

echo ">>>> cargo bench --no-run" && \
cargo bench --no-run && \

echo ">>>> cargo audit --deny warnings" && \
cargo audit --deny warnings && \

echo ">>>> cargo deny check" && \
cargo deny check

echo "Build Successful"