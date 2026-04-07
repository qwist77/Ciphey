# IMPORTANT: DO NOT IMPORT LARGE BRANCH ARTIFACTS

This branch salvages only the internet-search CTF writeup test workflow from `ares/codex/fix-ctf-writeup-search-flag`.

If you are copying files manually, or using an AI agent to do it for you, stop here first:

- Do not import the raw dirty branch.
- Do not copy any workspace dump just because it exists.
- Do not recreate Git LFS tracking for this feature.

## What This Branch Keeps

- `scripts/generate_ctf_writeup_tests.py`
- the handwritten and generated test harness under `tests/`
- a small public sample manifest at `data/ctf_writeup_inventory.json`
- docs for running the generator and tests

## What This Branch Intentionally Excludes

- `target/**`
- `tmp_*`
- `.codex`
- `_staging_anitools/**`
- `ctf-room-inventory.local.*`
- `ctf-platforms.local.md`
- `vendor/tokenizers/**`
- the dirty branch `.gitattributes`
- all `*.pyc`
- all `__pycache__/**`
- all binary cache outputs
- all tracked files larger than `1 MiB`

These files were excluded because they are either generated workspace artifacts, local-only research inputs, or oversized/LFS-backed content that is not required for the internet-search test feature.

## Local Full Inventory

If you want to use the full private/local inventory in a checkout, place it at:

`data/ctf_writeup_inventory.local.json`

and ignore it locally with:

`.git/info/exclude`

Do not add the full local inventory to tracked `.gitignore`, and do not commit it on this salvage branch.
