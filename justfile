build-all:
  cargo build
  docker build .

test-all:
  cargo build
  cargo check
  cargo clippy
  just test-core
  just test-corpus

test-core:
  cargo test --lib --bins --test integration_test --test ctf_writeups
  cargo test --doc

test-corpus:
  cargo test --test ctf_corpus_generated

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
