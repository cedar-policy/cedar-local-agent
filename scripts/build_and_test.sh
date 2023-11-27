#!/bin/sh

cd "$(dirname "$0")/.." || exit
START_TIME=$(date +%s)

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

echo ">>>> cargo test --verbose --no-default-features" && \
cargo test --verbose --no-default-features && \

echo ">>>> cargo test --verbose -- --ignored" && \
cargo test --verbose -- --ignored && \

echo ">>>> cargo bench --no-run" && \
cargo bench --no-run && \

echo ">>>> cargo audit --deny warnings" && \
cargo audit --deny warnings && \

echo ">>>> cargo deny check" && \
cargo deny check && \

echo ">>>> Removing old test coverage artifacts" && \
rm -rf target/coverage/ && mkdir -p target/coverage/ && \
rm -rf target/private/profraw/ && mkdir -p target/private/profraw/ && \

echo ">>>> Generating new test coverage profraw files" && \
RUSTFLAGS="-Cinstrument-coverage" LLVM_PROFILE_FILE="target/private/profraw/%p-%m.profraw" cargo test && \

echo ">>>> Generating new HTML test coverage report" && \
grcov 'target/private/profraw/' \
  -s '.' \
  --binary-path 'target/debug/deps' \
  -t html \
  --branch \
  --ignore-not-existing \
  -o 'target/coverage/' \
  --keep-only 'src/*' \
  --excl-start '\#\[cfg\(test\)\]' \
  --excl-stop '// GRCOV_BEGIN_COVERAGE' \
  --excl-line '\#\[derive\(' && \
echo "Successfully generated coverage report under target/coverage/"

END_TIME=$(date +%s)
echo "Build Successful in $(($END_TIME - $START_TIME)) seconds"
