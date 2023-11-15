#!/bin/sh

cd "$(dirname "$0")/.." || exit
rm -rf target/coverage/ && mkdir target/coverage/
rm -rf target/private/profraw/ && mkdir target/private/profraw/

RUSTFLAGS="-Cinstrument-coverage" LLVM_PROFILE_FILE="target/private/profraw/%p-%m.profraw" cargo test

grcov 'target/private/profraw/' \
  -s '.' \
  --binary-path 'target/debug/deps' \
  -t html \
  --branch \
  --ignore-not-existing \
  -o 'target/coverage/' \
  --keep-only 'src/*';

echo "Successfully generated coverage report under target/coverage/"