# CTF Writeup Corpus Tests

This branch preserves the internet-search test generator from `ares/codex/fix-ctf-writeup-search-flag` without importing the original workspace dump.

## Inventory Inputs

The generator reads one JSON inventory file:

- preferred local path: `data/ctf_writeup_inventory.local.json`
- committed fallback sample: `data/ctf_writeup_inventory.json`

Each entry must contain:

- `name`
- `platform`
- `url`
- optional `source`
- optional `metadata`

If both files exist, the generator uses the local file by default. You can override that with `--inventory-path`, or with the compatibility alias `--json-path`.

## Commands

Preflight only:

```bash
./scripts/generate_ctf_writeup_tests.py --preflight-only
```

Refresh generated tests:

```bash
just refresh-corpus-tests
```

Run the generated corpus offline:

```bash
just test-corpus
```

Equivalent direct test command:

```bash
cargo test --features ctf-corpus-tests --test ctf_writeups_generated
```

## Network Expectations

Refreshing the generated corpus requires:

- the `codex` CLI on `PATH`
- internet access for search

Running `just test-corpus` does not require internet access once the generated include file exists.

The checked-in `tests/generated/ctf_writeups_generated.inc.rs` file is intentionally empty on this branch. Refresh it locally when you are ready to run the internet-search workflow.

## Local-Only Full Inventory

Keep the large inventory local-only:

1. Copy it to `data/ctf_writeup_inventory.local.json`
2. Add that path to `.git/info/exclude`

Do not commit the local inventory. The committed sample manifest exists only to keep this branch pushable and reviewable.

## Omitted Branch Artifacts

Read [IMPORTANT_DO_NOT_IMPORT_LARGE_BRANCH_ARTIFACTS.md](../IMPORTANT_DO_NOT_IMPORT_LARGE_BRANCH_ARTIFACTS.md) before importing anything else from the dirty branch.
