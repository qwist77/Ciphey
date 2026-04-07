build-all:
  cargo build
  docker build .

test-all:
  cargo build
  cargo check
  cargo clippy
  cargo test

test-corpus:
  cargo test --features ctf-corpus-tests --test ctf_writeups_generated -- --quiet

refresh-corpus-tests:
  ./scripts/generate_ctf_writeup_tests.py
  cargo test --features ctf-corpus-tests --test ctf_writeups_generated -- --quiet

fix-all:
  git add .
  git commit -m 'Clippy and fmt'
  cargo clippy --fix
  cargo fmt
  cargo nextest run
  git add .
  git commit -m 'Clippy and fmt'

test:
  cargo nextest run

publish:
  docker buildx build --platform linux/arm/v7,linux/amd64,linux/arm64/v8 -t autumnskerritt/ciphey:latest --push .
