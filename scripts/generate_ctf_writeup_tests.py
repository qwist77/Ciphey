#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hashlib
import json
import atexit
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from typing import Any


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_LIST_PATH = REPO_ROOT / "ctf-room-inventory.local.md"
DEFAULT_JSON_PATH = REPO_ROOT / "ctf-room-inventory.local.json"
DEFAULT_OUTPUT_PATH = REPO_ROOT / "tests" / "generated" / "ctf_corpus_generated.inc.rs"
DEFAULT_REPORT_PATH = REPO_ROOT / "tmp_ctf_corpus_generated_report.json"
DEFAULT_MAX_WORKERS = 24
DEFAULT_VALIDATION_TIMEOUT_SECONDS = 120
GENERATOR_VERSION = 4
GENERATED_TEST_TARGET = "ctf_corpus_generated"
GENERATED_TEST_NAME_PREFIX = "ctf_corpus_"
PLATFORM_NAME_MAX_LEN = 12
ENTRY_NAME_MAX_LEN = 22
CASE_SLUG_MAX_LEN = 8


SUPPORTED_DECODER_TYPES = [
    "A1Z26Decoder",
    "AtbashDecoder",
    "Base32Decoder",
    "Base58BitcoinDecoder",
    "Base58FlickrDecoder",
    "Base58MoneroDecoder",
    "Base58RippleDecoder",
    "Base64Decoder",
    "Base65536Decoder",
    "Base91Decoder",
    "BinaryDecoder",
    "BrailleDecoder",
    "BrainfuckInterpreter",
    "CaesarDecoder",
    "HexadecimalDecoder",
    "MorseCodeDecoder",
    "ReverseDecoder",
    "ROT47Decoder",
    "SubstitutionGenericDecoder",
    "URLDecoder",
    "VigenereDecoder",
    "Z85Decoder",
]

SUPPORTED_DECODER_SET = set(SUPPORTED_DECODER_TYPES)
SUPPORTED_DECODER_ASSERTIONS = {"output", "candidates_contain"}


OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "status": {"type": "string", "enum": ["add_cases", "skip"]},
        "notes": {"type": "string"},
        "writeups_reviewed": {
            "type": "array",
            "items": {"type": "string"},
        },
        "cases": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "case_slug": {"type": "string"},
                    "encoded_text": {"type": "string"},
                    "expected_plaintext": {"type": "string"},
                    "decoder_type": {"type": "string"},
                    "decoder_assertion": {"type": "string"},
                    "rationale": {"type": "string"},
                },
                "required": [
                    "case_slug",
                    "encoded_text",
                    "expected_plaintext",
                    "decoder_type",
                    "decoder_assertion",
                    "rationale",
                ],
            },
        },
    },
    "required": ["status", "notes", "writeups_reviewed", "cases"],
}


TEST_FILE_HEADER = textwrap.dedent(
    """\
    // Generated from the recorded CTF corpus by scripts/generate_ctf_writeup_tests.py
    // Generated cases that fail local validation are emitted as ignored tests
    // instead of being dropped, so provenance stays checked in.
    """
)

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")
ANSI_COLOR_RED = "\033[31m"
ANSI_COLOR_GREEN = "\033[32m"
ANSI_COLOR_YELLOW = "\033[33m"
ANSI_COLOR_RESET = "\033[0m"


def strip_ansi_codes(value: str) -> str:
    return ANSI_ESCAPE_RE.sub("", value)


def stdout_supports_color() -> bool:
    if os.getenv("NO_COLOR") is not None:
        return False
    term = os.getenv("TERM", "")
    if term.lower() == "dumb":
        return False
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


def colorize_log_line(value: str, color: str | None = None) -> str:
    if not color or not stdout_supports_color():
        return value
    return f"{color}{value}{ANSI_COLOR_RESET}"


class TeeOutput:
    def __init__(self, output_path: pathlib.Path) -> None:
        self._output_path = output_path
        self._file: Any | None = None
        self._previous_stdout = None
        self._previous_stderr = None

    def __enter__(self) -> "TeeOutput":
        self._output_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = self._output_path.open("a", encoding="utf-8", buffering=1)
        self._previous_stdout = sys.stdout
        self._previous_stderr = sys.stderr
        sys.stdout = self
        sys.stderr = self
        return self

    def write(self, value: str) -> None:
        if self._previous_stdout is not None:
            self._previous_stdout.write(value)
        if self._file is not None:
            self._file.write(strip_ansi_codes(value))

    def flush(self) -> None:
        if self._previous_stdout is not None:
            self._previous_stdout.flush()
        if self._file is not None:
            self._file.flush()

    def isatty(self) -> bool:
        return bool(self._previous_stdout is not None and self._previous_stdout.isatty())

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._previous_stdout is not None:
            sys.stdout = self._previous_stdout
            sys.stderr = self._previous_stderr
            self._previous_stdout = None
            self._previous_stderr = None
        if self._file is not None:
            self._file.close()
            self._file = None


@dataclasses.dataclass(frozen=True)
class InventoryItem:
    index: int
    name: str
    platform: str
    url: str
    source: str
    metadata: dict[str, Any]
    suggested_case_prefix: str


@dataclasses.dataclass(frozen=True)
class AgentCase:
    case_slug: str
    encoded_text: str
    expected_plaintext: str
    decoder_type: str | None
    decoder_assertion: str | None
    rationale: str


@dataclasses.dataclass
class AgentResult:
    item: InventoryItem
    status: str
    notes: str
    writeups_reviewed: list[str]
    cases: list[AgentCase]
    error: str | None = None
    attempts: int = 1


@dataclasses.dataclass(frozen=True)
class RenderedCase:
    item: InventoryItem
    case: AgentCase
    base_name: str
    test_bodies: tuple[str, ...]
    test_names: tuple[str, ...]
    disabled_reason: str | None = None


@dataclasses.dataclass(frozen=True)
class ValidationResult:
    passed: bool
    reason: str


class StopController:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._reason = ""
        self._requested = False
        self._announced = False

    def request(self, reason: str) -> bool:
        with self._lock:
            first_request = not self._requested
            if first_request:
                self._requested = True
                self._reason = reason
            return first_request

    @property
    def requested(self) -> bool:
        with self._lock:
            return self._requested

    @property
    def reason(self) -> str:
        with self._lock:
            return self._reason

    def mark_announced(self) -> bool:
        with self._lock:
            if self._announced:
                return False
            self._announced = True
            return True


class TtyStopWatcher:
    def __init__(self, stop_controller: StopController) -> None:
        self._stop_controller = stop_controller
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._tty_fd: int | None = None
        self._saved_termios: list[Any] | None = None

    def __enter__(self) -> "TtyStopWatcher":
        if not sys.stdin.isatty():
            return self

        try:
            import termios
            import tty
        except ImportError:
            return self

        try:
            self._tty_fd = sys.stdin.fileno()
            self._saved_termios = termios.tcgetattr(self._tty_fd)
            tty.setcbreak(self._tty_fd)
        except OSError:
            self._tty_fd = None
            self._saved_termios = None
            return self

        def watch_stdin() -> None:
            assert self._tty_fd is not None
            while not self._stop_event.is_set():
                try:
                    chunk = os.read(self._tty_fd, 1)
                except OSError:
                    return
                if not chunk:
                    return
                if chunk == b"\x18":
                    if self._stop_controller.request("Ctrl+X requested stop"):
                        print(
                            colorize_log_line(
                                "[CONTROL] Ctrl+X received; checkpoint stop requested. "
                                "Finishing in-flight work and saving progress.",
                                ANSI_COLOR_YELLOW,
                            ),
                            flush=True,
                        )
                    return

        self._thread = threading.Thread(target=watch_stdin, name="ctf-stop-watcher", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self._stop_event.set()
        if self._saved_termios is not None and self._tty_fd is not None:
            try:
                import termios

                termios.tcsetattr(self._tty_fd, termios.TCSADRAIN, self._saved_termios)
            except OSError:
                pass


def rust_ident(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "_", value)
    value = value.strip("_")
    if not value:
        value = "ctf"
    if value[0].isdigit():
        value = f"ctf_{value}"
    return value


def shorten_rust_ident(value: str, max_len: int) -> str:
    ident = rust_ident(value)
    if len(ident) <= max_len:
        return ident

    digest = hashlib.sha1(ident.encode("utf-8")).hexdigest()[:10]
    keep = max(8, max_len - len(digest) - 1)
    trimmed = ident[:keep].rstrip("_")
    return f"{trimmed}_{digest}"


def normalize_inventory_name(value: str) -> str:
    return value.replace("\u00a0", " ").strip()


def normalize_optional_string(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()


def load_inventory(list_path: pathlib.Path, json_path: pathlib.Path) -> list[InventoryItem]:
    lines = [line.strip() for line in list_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    data = json.loads(json_path.read_text(encoding="utf-8"))
    entries = data["entries"]

    if len(lines) != len(entries):
        raise RuntimeError(
            f"inventory list length ({len(lines)}) does not match JSON entries ({len(entries)})"
        )

    items: list[InventoryItem] = []
    for index, (line_name, entry) in enumerate(zip(lines, entries, strict=True), start=1):
        entry_name = normalize_inventory_name(entry["name"])
        if line_name != entry_name:
            raise RuntimeError(
                f"inventory mismatch at line {index}: list has {line_name!r}, json has {entry_name!r}"
            )

        suggested_case_prefix = (
            f"{shorten_rust_ident(entry['platform'], PLATFORM_NAME_MAX_LEN)}_"
            f"{shorten_rust_ident(entry_name, ENTRY_NAME_MAX_LEN)}_"
            f"{index}"
        )

        items.append(
            InventoryItem(
                index=index,
                name=entry_name,
                platform=entry["platform"],
                url=entry["url"],
                source=normalize_optional_string(entry.get("source", "")),
                metadata=entry.get("metadata", {}),
                suggested_case_prefix=suggested_case_prefix,
            )
        )

    return items


def default_worker_count(item_count: int) -> int:
    if item_count <= 0:
        return 1

    cpu_count = os.cpu_count() or 8
    return min(item_count, max(4, min(DEFAULT_MAX_WORKERS, cpu_count * 2)))


def require_command(name: str) -> str:
    command_path = shutil.which(name)
    if not command_path:
        raise RuntimeError(f"required command not found on PATH: {name}")
    return command_path


def resolve_output_path(repo_root: pathlib.Path, output_path: pathlib.Path) -> pathlib.Path:
    resolved = output_path.resolve()
    tests_dir = (repo_root / "tests").resolve()

    if resolved.suffix != ".rs":
        raise RuntimeError(f"--output-path must end in .rs: {resolved}")

    try:
        resolved.relative_to(tests_dir)
    except ValueError as exc:
        raise RuntimeError(f"--output-path must live under {tests_dir}") from exc

    return resolved


def normalize_writeups(raw_writeups: Any) -> list[str]:
    if not isinstance(raw_writeups, list):
        return []

    deduped_writeups: list[str] = []
    seen_writeups: set[str] = set()
    for value in raw_writeups:
        if not isinstance(value, str):
            continue
        cleaned = value.strip()
        if not cleaned or cleaned in seen_writeups:
            continue
        seen_writeups.add(cleaned)
        deduped_writeups.append(cleaned)

    return deduped_writeups


def looks_like_quota_or_token_exhaustion(error: str | None) -> bool:
    if not error:
        return False

    lowered = error.lower()
    indicators = [
        "insufficient_quota",
        "quota",
        "rate limit",
        "rate-limit",
        "too many requests",
        "usage limit",
        "billing",
        "credits",
        "token limit",
        "tokens exhausted",
        "exceeded your current quota",
    ]
    return any(indicator in lowered for indicator in indicators)


def build_prompt(item: InventoryItem) -> str:
    entry_json = json.dumps(
        {
            "index": item.index,
            "name": item.name,
            "platform": item.platform,
            "url": item.url,
            "source": item.source,
            "metadata": item.metadata,
            "suggested_case_prefix": item.suggested_case_prefix,
        },
        indent=2,
        ensure_ascii=False,
    )

    decoder_list = ", ".join(SUPPORTED_DECODER_TYPES)

    return textwrap.dedent(
        f"""\
        You are auditing exactly one CTF entry in the local Ciphey repository.

        Requirements:
        - Search the web for writeups for this exact CTF entry.
        - Read at least 2 independent writeups. Read a third if available.
        - Extract every encoded string in those writeups that has:
          - an exact encoded input string
          - an exact final plaintext string
        - Include both easy single-step examples and multi-step examples when the final plaintext is explicit.
        - Do not edit any local files. Return JSON only.

        Important rules:
        - If you cannot review at least 2 independent writeups, return "skip".
        - Do not drop a case just because Ciphey might fail it today.
        - Do include exact encoded/plaintext pairs even when Ciphey does not fully support them yet.
        - If a case is useful but does not map cleanly to a currently supported direct decoder, still include it and leave
          decoder_type and decoder_assertion empty.
        - Only include cases where the encoded string can be copied exactly into a Rust string literal.
        - Only include cases where the expected plaintext is explicit and unambiguous.
        - If the writeup clearly identifies a single direct decoder already present in this repository for the exact string,
          set decoder_type and decoder_assertion.
        - If the case is multi-step, ambiguous, or the direct decoder is not explicit, leave decoder_type and
          decoder_assertion as empty strings.

        Supported direct decoders:
        {decoder_list}

        Allowed decoder_assertion values:
        - output
        - candidates_contain
        - empty string when no direct decoder test should be generated

        Return JSON matching the schema with:
        - status: "add_cases" or "skip"
        - notes: short summary of the decision
        - writeups_reviewed: the exact writeup URLs you actually reviewed
        - cases: every extracted case, where each case contains:
          - case_slug: short stable slug like "rot13_hint" or "base64_flag"
          - encoded_text: the exact encoded string
          - expected_plaintext: the exact final plaintext
          - decoder_type: supported decoder type or empty string
          - decoder_assertion: "output", "candidates_contain", or empty string
          - rationale: short sentence for why this case is useful

        Inventory entry:
        {entry_json}
        """
    )


def finalize_codex_payload(item: InventoryItem, payload: dict[str, Any]) -> AgentResult:
    required_keys = {"status", "notes", "writeups_reviewed", "cases"}
    missing_keys = sorted(required_keys.difference(payload))
    if missing_keys:
        return AgentResult(
            item=item,
            status="skip",
            notes="codex returned incomplete JSON payload",
            writeups_reviewed=[],
            cases=[],
            error=f"missing keys: {', '.join(missing_keys)}",
        )

    status = payload["status"]
    if status not in {"add_cases", "skip"}:
        return AgentResult(
            item=item,
            status="skip",
            notes="codex returned invalid status",
            writeups_reviewed=[],
            cases=[],
            error=f"invalid status: {status!r}",
        )

    writeups_reviewed = normalize_writeups(payload["writeups_reviewed"])
    if status == "add_cases" and len(writeups_reviewed) < 2:
        return AgentResult(
            item=item,
            status="skip",
            notes="codex reviewed fewer than 2 writeups",
            writeups_reviewed=writeups_reviewed,
            cases=[],
            error="fewer than 2 independent writeups reviewed",
        )

    raw_cases = payload["cases"]
    if not isinstance(raw_cases, list):
        return AgentResult(
            item=item,
            status="skip",
            notes="codex returned invalid cases list",
            writeups_reviewed=writeups_reviewed,
            cases=[],
            error="cases was not a list",
        )

    cases: list[AgentCase] = []
    seen_pairs: set[tuple[str, str]] = set()
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict):
            continue

        case_slug = normalize_optional_string(raw_case.get("case_slug"))
        encoded_text = normalize_optional_string(raw_case.get("encoded_text"))
        expected_plaintext = normalize_optional_string(raw_case.get("expected_plaintext"))
        decoder_type = normalize_optional_string(raw_case.get("decoder_type"))
        decoder_assertion = normalize_optional_string(raw_case.get("decoder_assertion"))
        rationale = normalize_optional_string(raw_case.get("rationale"))

        if not case_slug or not encoded_text or not expected_plaintext or not rationale:
            continue

        pair_key = (encoded_text, expected_plaintext)
        if pair_key in seen_pairs:
            continue
        seen_pairs.add(pair_key)

        if decoder_type not in SUPPORTED_DECODER_SET:
            decoder_type = ""

        if not decoder_type or decoder_assertion not in SUPPORTED_DECODER_ASSERTIONS:
            decoder_type = ""
            decoder_assertion = ""

        cases.append(
            AgentCase(
                case_slug=case_slug,
                encoded_text=encoded_text,
                expected_plaintext=expected_plaintext,
                decoder_type=decoder_type or None,
                decoder_assertion=decoder_assertion or None,
                rationale=rationale,
            )
        )

    if status == "add_cases" and not cases:
        return AgentResult(
            item=item,
            status="skip",
            notes="codex returned no valid cases",
            writeups_reviewed=writeups_reviewed,
            cases=[],
            error="no valid cases extracted from payload",
        )

    return AgentResult(
        item=item,
        status=status,
        notes=normalize_optional_string(payload["notes"]) or "no notes provided",
        writeups_reviewed=writeups_reviewed,
        cases=cases,
        error=None,
    )


def run_codex_once(
    item: InventoryItem,
    repo_root: pathlib.Path,
    codex_binary: str,
    timeout_seconds: int,
    model: str,
    reasoning_effort: str,
) -> AgentResult:
    prompt = build_prompt(item)

    with tempfile.TemporaryDirectory(prefix="ctf-agent-") as temp_dir_str:
        temp_dir = pathlib.Path(temp_dir_str)
        schema_path = temp_dir / "schema.json"
        output_path = temp_dir / "result.json"

        schema_path.write_text(json.dumps(OUTPUT_SCHEMA, indent=2), encoding="utf-8")

        command = [
            codex_binary,
            "--search",
            "exec",
            "--ephemeral",
            "--dangerously-bypass-approvals-and-sandbox",
            "-m",
            model,
            "-c",
            f'model_reasoning_effort="{reasoning_effort}"',
            "-C",
            str(repo_root),
            "--output-schema",
            str(schema_path),
            "-o",
            str(output_path),
        ]

        try:
            completed = subprocess.run(
                command,
                input=prompt,
                text=True,
                cwd=repo_root,
                capture_output=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            return AgentResult(
                item=item,
                status="skip",
                notes="codex timed out",
                writeups_reviewed=[],
                cases=[],
                error="timeout",
            )

        if completed.returncode != 0:
            stderr = completed.stderr.strip() or completed.stdout.strip() or "codex failed"
            return AgentResult(
                item=item,
                status="skip",
                notes="codex failed",
                writeups_reviewed=[],
                cases=[],
                error=stderr[:2000],
            )

        if not output_path.exists():
            return AgentResult(
                item=item,
                status="skip",
                notes="codex returned no output file",
                writeups_reviewed=[],
                cases=[],
                error="missing output file",
            )

        try:
            payload = json.loads(output_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return AgentResult(
                item=item,
                status="skip",
                notes="codex returned invalid JSON",
                writeups_reviewed=[],
                cases=[],
                error=str(exc),
            )

    return finalize_codex_payload(item, payload)


def should_retry_codex_result(result: AgentResult) -> bool:
    if result.error is None:
        return False

    retryable_notes = {
        "codex timed out",
        "codex failed",
        "codex returned no output file",
        "codex returned invalid JSON",
        "codex returned incomplete JSON payload",
        "codex returned invalid status",
        "codex returned invalid cases list",
    }
    return result.notes in retryable_notes


def run_codex_with_retries(
    item: InventoryItem,
    repo_root: pathlib.Path,
    codex_binary: str,
    timeout_seconds: int,
    model: str,
    reasoning_effort: str,
    max_retries: int,
    retry_backoff_seconds: float,
) -> AgentResult:
    attempts = max(1, max_retries + 1)
    last_result: AgentResult | None = None

    for attempt in range(1, attempts + 1):
        result = run_codex_once(
            item,
            repo_root,
            codex_binary,
            timeout_seconds,
            model,
            reasoning_effort,
        )
        result.attempts = attempt

        if not should_retry_codex_result(result) or attempt == attempts:
            return result

        last_result = result
        time.sleep(retry_backoff_seconds * attempt)

    if last_result is not None:
        return last_result

    return AgentResult(
        item=item,
        status="skip",
        notes="codex failed before any attempt completed",
        writeups_reviewed=[],
        cases=[],
        error="no attempts completed",
        attempts=attempts,
    )


def load_existing_test_names(repo_root: pathlib.Path, output_path: pathlib.Path) -> set[str]:
    test_name_re = re.compile(r"fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    names: set[str] = set()

    for path in (repo_root / "tests").rglob("*.rs"):
        if path.resolve() == output_path:
            continue
        text = path.read_text(encoding="utf-8")
        names.update(test_name_re.findall(text))

    return names


def stable_case_base_name(item: InventoryItem, case: AgentCase) -> str:
    slug = shorten_rust_ident(case.case_slug, CASE_SLUG_MAX_LEN)
    digest = hashlib.sha1(
        f"{case.encoded_text}\0{case.expected_plaintext}".encode("utf-8")
    ).hexdigest()[:10]
    return f"{GENERATED_TEST_NAME_PREFIX}{item.suggested_case_prefix}_{slug}_{digest}"


def rust_string_literal(value: str) -> str:
    escaped_parts: list[str] = ['"']
    for char in value:
        if char == "\\":
            escaped_parts.append("\\\\")
        elif char == '"':
            escaped_parts.append('\\"')
        elif char == "\n":
            escaped_parts.append("\\n")
        elif char == "\r":
            escaped_parts.append("\\r")
        elif char == "\t":
            escaped_parts.append("\\t")
        elif char == "\0":
            escaped_parts.append("\\0")
        elif ord(char) < 0x20 or ord(char) == 0x7F:
            escaped_parts.append(f"\\u{{{ord(char):x}}}")
        else:
            escaped_parts.append(char)
    escaped_parts.append('"')
    return "".join(escaped_parts)


def indent_lines(lines: list[str], spaces: int = 4) -> str:
    prefix = " " * spaces
    return "\n".join(f"{prefix}{line}" for line in lines)


def provenance_lines(item: InventoryItem, case: AgentCase, writeups_reviewed: list[str]) -> list[str]:
    lines = [
        f"// CTF Name: {item.name}",
        f"// Platform: {item.platform}",
        f"// Inventory URL: {item.url}",
        f"// Inventory Source: {item.source or 'same as inventory URL'}",
    ]
    for index, writeup_url in enumerate(writeups_reviewed, start=1):
        lines.append(f"// Writeup URL {index}: {writeup_url}")
    lines.append(f"// Decoder Path: {decode_path_label(case)}")
    lines.append(f"// Decryption intent: {decode_intent_label(case)}")
    lines.append(f"// Why this test exists: {case.rationale}")
    return lines


def decode_intent_label(case: AgentCase) -> str:
    return normalize_comment_text(case.rationale, max_len=120)


def decode_path_label(case: AgentCase) -> str:
    if case.decoder_type:
        pretty = pretty_decoder_name(case.decoder_type)
        assertion = case.decoder_assertion or "output"
        return f"{pretty} direct decoder (assertion={assertion})"

    assertion = case.decoder_assertion or "output"
    return f"undetermined transform chain (assertion={assertion})"


def pretty_decoder_name(decoder_type: str) -> str:
    pretty = re.sub(r"([A-Z])", r" \1", decoder_type.replace("Decoder", "").strip()).strip()
    if not pretty:
        return decoder_type
    return pretty


def normalize_comment_text(value: str, max_len: int = 120) -> str:
    compact = " ".join(value.split())
    if len(compact) > max_len:
        return f"{compact[:max_len - 3]}..."
    return compact


def item_log_label(item: InventoryItem) -> str:
    return f"{item.index}: {item.platform} / {item.name}"


def render_perform_cracking_test(
    item: InventoryItem,
    case: AgentCase,
    writeups_reviewed: list[str],
    test_name: str,
) -> str:
    lines = [
        "#[test]",
        "#[serial]",
        f"fn {test_name}() {{",
        indent_lines(provenance_lines(item, case, writeups_reviewed)),
        (
            f"    assert_perform_cracking_contains("
            f"{rust_string_literal(case.encoded_text)}, "
            f"{rust_string_literal(case.expected_plaintext)}"
            ");"
        ),
        "}",
    ]
    return "\n".join(lines)


def render_decoder_test(
    item: InventoryItem,
    case: AgentCase,
    writeups_reviewed: list[str],
    test_name: str,
) -> str:
    assertion_fn = (
        "assert_decoder_output"
        if case.decoder_assertion == "output"
        else "assert_decoder_candidates_contain"
    )
    lines = [
        "#[test]",
        f"fn {test_name}() {{",
        indent_lines(
            provenance_lines(item, case, writeups_reviewed)
            + [f"// Direct Decoder: {case.decoder_type}"]
        ),
        (
            f"    {assertion_fn}::<{case.decoder_type}>("
            f"{rust_string_literal(case.encoded_text)}, "
            f"{rust_string_literal(case.expected_plaintext)}"
            ");"
        ),
        "}",
    ]
    return "\n".join(lines)


def validate_and_render_cases(
    result: AgentResult,
    used_names: set[str],
) -> tuple[list[RenderedCase], list[str]]:
    rendered_cases: list[RenderedCase] = []
    validation_errors: list[str] = []

    if result.status != "add_cases":
        return rendered_cases, validation_errors

    if len(result.writeups_reviewed) < 2:
        validation_errors.append("reviewed fewer than 2 writeups")
        return rendered_cases, validation_errors

    reserved_names: set[str] = set()
    for case in result.cases:
        base_name = stable_case_base_name(result.item, case)
        perform_test_name = f"{base_name}_perform_cracking"
        candidate_names = [perform_test_name]

        direct_test_name: str | None = None
        if case.decoder_type:
            direct_test_name = f"{base_name}_decoder"
            candidate_names.append(direct_test_name)

        collided_name = next(
            (name for name in candidate_names if name in used_names or name in reserved_names),
            None,
        )
        if collided_name is not None:
            validation_errors.append(f"name collision: {collided_name}")
            continue

        test_bodies = [
            render_perform_cracking_test(result.item, case, result.writeups_reviewed, perform_test_name)
        ]
        test_names = [perform_test_name]

        if direct_test_name is not None:
            test_bodies.append(
                render_decoder_test(result.item, case, result.writeups_reviewed, direct_test_name)
            )
            test_names.append(direct_test_name)

        reserved_names.update(candidate_names)
        rendered_cases.append(
            RenderedCase(
                item=result.item,
                case=case,
                base_name=base_name,
                test_bodies=tuple(test_bodies),
                test_names=tuple(test_names),
            )
        )

    return rendered_cases, validation_errors


def render_test_file(rendered_cases: list[RenderedCase]) -> str:
    body_parts: list[str] = []
    for rendered_case in sorted(rendered_cases, key=lambda value: value.base_name):
        body_parts.extend(rendered_case.test_bodies)

    body = "\n\n".join(body_parts).strip()
    if body:
        return f"{TEST_FILE_HEADER.rstrip()}\n\n{body}\n"
    return f"{TEST_FILE_HEADER.rstrip()}\n"


def normalize_disable_reason(reason: str) -> str:
    compact = " ".join(reason.split())
    if not compact:
        return "generated case failed local validation"
    return compact[:160]


def disable_test_body(body: str, reason: str) -> str:
    normalized_reason = normalize_disable_reason(reason)
    return "\n".join(
        [
            f"// Auto-disabled by generator: {normalized_reason}",
            f"#[ignore = {rust_string_literal(normalized_reason)}]",
            body,
        ]
    )


def disable_rendered_case(rendered_case: RenderedCase, reason: str) -> RenderedCase:
    normalized_reason = normalize_disable_reason(reason)
    return dataclasses.replace(
        rendered_case,
        test_bodies=tuple(disable_test_body(body, normalized_reason) for body in rendered_case.test_bodies),
        disabled_reason=normalized_reason,
    )


def serialize_rendered_case(rendered_case: RenderedCase) -> dict[str, Any]:
    return {
        "item_index": rendered_case.item.index,
        "base_name": rendered_case.base_name,
        "disabled_reason": rendered_case.disabled_reason or "",
        "case": {
            "case_slug": rendered_case.case.case_slug,
            "encoded_text": rendered_case.case.encoded_text,
            "expected_plaintext": rendered_case.case.expected_plaintext,
            "decoder_type": rendered_case.case.decoder_type or "",
            "decoder_assertion": rendered_case.case.decoder_assertion or "",
            "rationale": rendered_case.case.rationale,
        },
        "test_bodies": list(rendered_case.test_bodies),
        "test_names": list(rendered_case.test_names),
    }


def deserialize_rendered_case(
    payload: dict[str, Any],
    inventory_by_index: dict[int, InventoryItem],
) -> RenderedCase | None:
    item_index = payload.get("item_index")
    if not isinstance(item_index, int):
        return None
    item = inventory_by_index.get(item_index)
    if item is None:
        return None

    case_payload = payload.get("case")
    if not isinstance(case_payload, dict):
        return None

    test_bodies = payload.get("test_bodies")
    test_names = payload.get("test_names")
    base_name = payload.get("base_name")
    disabled_reason = normalize_optional_string(payload.get("disabled_reason"))
    if not isinstance(test_bodies, list) or not isinstance(test_names, list) or not isinstance(base_name, str):
        return None

    if not all(isinstance(value, str) for value in test_bodies + test_names):
        return None

    case = AgentCase(
        case_slug=normalize_optional_string(case_payload.get("case_slug")),
        encoded_text=normalize_optional_string(case_payload.get("encoded_text")),
        expected_plaintext=normalize_optional_string(case_payload.get("expected_plaintext")),
        decoder_type=normalize_optional_string(case_payload.get("decoder_type")) or None,
        decoder_assertion=normalize_optional_string(case_payload.get("decoder_assertion")) or None,
        rationale=normalize_optional_string(case_payload.get("rationale")),
    )

    if not case.case_slug or not case.encoded_text or not case.expected_plaintext or not case.rationale:
        return None

    return RenderedCase(
        item=item,
        case=case,
        base_name=base_name,
        test_bodies=tuple(test_bodies),
        test_names=tuple(test_names),
        disabled_reason=disabled_reason or None,
    )


def refresh_report_summary(report: dict[str, Any], inventory_items: int) -> None:
    processed_item_details = report.setdefault("processed_item_details", [])
    accepted_item_details = report.setdefault("accepted_item_details", [])
    accepted_case_details = report.setdefault("accepted_case_details", [])
    in_flight_item_indices = report.setdefault("in_flight_item_indices", [])

    report["inventory_items"] = inventory_items
    report["processed_items"] = len(processed_item_details)
    report["remaining_items"] = max(0, inventory_items - len(processed_item_details))
    report["accepted_items"] = len(accepted_item_details)
    report["accepted_cases"] = len(accepted_case_details)
    report["in_flight_items"] = len(in_flight_item_indices)
    report["disabled_cases"] = sum(1 for entry in accepted_case_details if entry.get("disabled_reason"))
    report["rendered_tests"] = sum(len(entry.get("test_names", [])) for entry in accepted_case_details)
    report["skipped_items"] = sum(1 for entry in processed_item_details if entry.get("status") != "accepted")
    report["agent_errors"] = sum(1 for entry in processed_item_details if entry.get("had_error"))
    report["validation_failures"] = sum(
        len(entry.get("validation_errors", [])) for entry in processed_item_details
    )
    report["rejected_cases"] = report["validation_failures"]


def format_duration(seconds: float) -> str:
    total_seconds = max(0, int(seconds))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, secs = divmod(remainder, 60)

    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def progress_summary(
    report: dict[str, Any],
    inventory_items: int,
    *,
    run_started_at: float | None = None,
    initial_processed_count: int = 0,
) -> str:
    processed_count = len(report.get("processed_item_details", []))
    accepted_count = len(report.get("accepted_item_details", []))
    skipped_count = max(0, processed_count - accepted_count)
    in_flight_count = len(report.get("in_flight_item_indices", []))
    disabled_count = sum(
        len(entry.get("disabled_case_details", [])) for entry in report.get("accepted_item_details", [])
    )

    if inventory_items <= 0:
        percent = 100.0
    else:
        percent = processed_count * 100.0 / inventory_items

    summary = (
        f"{processed_count}/{inventory_items} ({percent:.1f}%) processed | "
        f"accepted {accepted_count} | skipped {skipped_count} | in-flight {in_flight_count} | disabled {disabled_count}"
    )

    if run_started_at is None:
        return summary

    elapsed_seconds = max(0.0, time.monotonic() - run_started_at)
    processed_this_run = max(0, processed_count - initial_processed_count)
    if processed_this_run <= 0 or elapsed_seconds <= 0:
        return f"{summary} | rate n/a | ETA n/a"

    items_per_minute = processed_this_run * 60.0 / elapsed_seconds
    remaining_items = max(0, inventory_items - processed_count)
    eta_seconds = 0.0 if remaining_items == 0 else (remaining_items * 60.0 / items_per_minute)
    return f"{summary} | rate {items_per_minute:.2f}/min | ETA {format_duration(eta_seconds)}"


def write_report(report_path: pathlib.Path, report: dict[str, Any], inventory_items: int) -> None:
    refresh_report_summary(report, inventory_items)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def request_stop(report: dict[str, Any], stop_controller: StopController, reason: str) -> None:
    if stop_controller.request(reason):
        report["aborted"] = True
        report["abort_reason"] = reason


def load_resume_state(
    report_path: pathlib.Path,
    inventory_by_index: dict[int, InventoryItem],
    inventory_items: int,
    output_path: pathlib.Path,
    list_path: pathlib.Path,
    json_path: pathlib.Path,
) -> tuple[dict[str, Any], list[RenderedCase], set[int], set[str], list[int]] | None:
    if not report_path.exists():
        return None

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None

    if not isinstance(report, dict):
        return None

    if report.get("generator_version") != GENERATOR_VERSION:
        return None
    if report.get("output_path") != str(output_path):
        return None
    if report.get("list_path") != str(list_path):
        return None
    if report.get("json_path") != str(json_path):
        return None

    rendered_cases: list[RenderedCase] = []
    used_names: set[str] = set()
    for entry in report.get("accepted_case_details", []):
        if not isinstance(entry, dict):
            continue
        rendered_case = deserialize_rendered_case(entry, inventory_by_index)
        if rendered_case is None:
            continue
        rendered_cases.append(rendered_case)
        used_names.update(rendered_case.test_names)

    processed_indices: set[int] = set()
    for entry in report.get("processed_item_details", []):
        if not isinstance(entry, dict):
            continue
        item_index = entry.get("index")
        if isinstance(item_index, int):
            processed_indices.add(item_index)

    in_flight_indices: list[int] = []
    for item_index in report.get("in_flight_item_indices", []):
        if not isinstance(item_index, int):
            continue
        if item_index in processed_indices:
            continue
        if item_index not in inventory_by_index:
            continue
        if item_index in in_flight_indices:
            continue
        in_flight_indices.append(item_index)

    refresh_report_summary(report, inventory_items)
    return report, rendered_cases, processed_indices, used_names, in_flight_indices


def write_output_file(output_path: pathlib.Path, rendered_cases: list[RenderedCase]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        render_test_file(rendered_cases),
        encoding="utf-8",
        newline="\n",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate CTF writeup tests with codex agents.")
    parser.add_argument("--list-path", type=pathlib.Path, default=DEFAULT_LIST_PATH)
    parser.add_argument("--json-path", type=pathlib.Path, default=DEFAULT_JSON_PATH)
    parser.add_argument("--output-path", type=pathlib.Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument(
        "--model",
        default="gpt-5.4-mini",
        help="Codex model to use for each worker. Use gpt-5.4 for the larger model.",
    )
    parser.add_argument(
        "--reasoning-effort",
        default="xhigh",
        help="Codex reasoning effort passed through config.",
    )
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument(
        "--max-retries",
        type=int,
        default=2,
        help="How many times to retry a Codex worker after retryable failures such as timeout, non-zero exit, or invalid payload.",
    )
    parser.add_argument(
        "--retry-backoff-seconds",
        type=float,
        default=2.0,
        help="Base delay between Codex retries. Actual sleep grows linearly by attempt number.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=0,
        help=f"0 means use the script default worker count (currently capped at {DEFAULT_MAX_WORKERS}).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Limit how many inventory items are processed. 0 means process them all.",
    )
    parser.add_argument(
        "--only-index",
        type=int,
        default=0,
        help="Process only one inventory index. 0 means do not filter by a single index.",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Ignore any existing report/output state and start from scratch.",
    )
    parser.add_argument(
        "--report-file",
        type=pathlib.Path,
        default=DEFAULT_REPORT_PATH,
        help=f"JSON report output path. Defaults to {DEFAULT_REPORT_PATH}.",
    )
    parser.add_argument(
        "--log-file",
        type=pathlib.Path,
        help="Write all runtime logs into this file in addition to stdout. Defaults to the report path with a .log suffix.",
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Validate inventory, toolchain, and output paths without spawning Codex agents.",
    )
    parser.add_argument(
        "--validation-timeout-seconds",
        type=int,
        default=DEFAULT_VALIDATION_TIMEOUT_SECONDS,
        help="Timeout for validating one generated case with cargo test.",
    )
    parser.add_argument(
        "--cargo-test-target",
        default=GENERATED_TEST_TARGET,
        help="Integration test target used to validate generated cases.",
    )
    parser.add_argument(
        "--no-validate-generated-tests",
        action="store_true",
        help="Skip cargo test validation for newly generated cases.",
    )
    parser.add_argument(
        "--no-validation-offline",
        action="store_true",
        help="Run cargo test validation without --offline.",
    )
    return parser.parse_args()


def make_empty_report(args: argparse.Namespace, codex_binary: str) -> dict[str, Any]:
    return {
        "generator_version": GENERATOR_VERSION,
        "codex_binary": codex_binary,
        "output_path": str(args.output_path),
        "report_file": str(args.report_file),
        "log_file": str(args.log_file),
        "list_path": str(args.list_path),
        "json_path": str(args.json_path),
        "workers": args.workers,
        "max_retries": args.max_retries,
        "retry_backoff_seconds": args.retry_backoff_seconds,
        "validation_timeout_seconds": args.validation_timeout_seconds,
        "cargo_test_target": args.cargo_test_target,
        "validate_generated_tests": not args.no_validate_generated_tests,
        "validation_offline": not args.no_validation_offline,
        "accepted_item_details": [],
        "accepted_case_details": [],
        "processed_item_details": [],
        "in_flight_item_indices": [],
        "aborted": False,
        "abort_reason": "",
    }


def validate_rendered_case(
    repo_root: pathlib.Path,
    cargo_binary: str,
    cargo_test_target: str,
    rendered_case: RenderedCase,
    timeout_seconds: int,
    offline: bool,
) -> ValidationResult:
    command = [cargo_binary, "test"]
    if offline:
        command.append("--offline")
    command.extend(
        [
            "--test",
            cargo_test_target,
            rendered_case.base_name,
        ]
    )

    try:
        completed = subprocess.run(
            command,
            cwd=repo_root,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return ValidationResult(False, "generated case timed out during cargo test validation")

    if completed.returncode == 0:
        return ValidationResult(True, "")

    return ValidationResult(False, "generated case failed cargo test validation")


def main() -> int:
    args = parse_args()
    args.list_path = args.list_path.resolve()
    args.json_path = args.json_path.resolve()
    args.output_path = resolve_output_path(REPO_ROOT, args.output_path)
    args.report_file = args.report_file.resolve()
    if args.log_file is None:
        args.log_file = args.report_file.with_suffix(".log")
    else:
        args.log_file = args.log_file.resolve()
    log_output = TeeOutput(args.log_file)
    log_output.__enter__()
    atexit.register(log_output.__exit__, None, None, None)

    if args.max_retries < 0:
        raise RuntimeError("--max-retries must be >= 0")
    if args.retry_backoff_seconds < 0:
        raise RuntimeError("--retry-backoff-seconds must be >= 0")
    if args.limit < 0:
        raise RuntimeError("--limit must be >= 0")
    if args.only_index < 0:
        raise RuntimeError("--only-index must be >= 0")
    if args.validation_timeout_seconds <= 0:
        raise RuntimeError("--validation-timeout-seconds must be > 0")

    codex_binary = require_command("codex")
    cargo_binary = require_command("cargo")

    items = load_inventory(args.list_path, args.json_path)
    if args.only_index:
        items = [item for item in items if item.index == args.only_index]
        if not items:
            raise RuntimeError(f"--only-index did not match any inventory entry: {args.only_index}")
    if args.limit:
        items = items[: args.limit]

    inventory_by_index = {item.index: item for item in items}
    workers = args.workers or default_worker_count(len(items))
    used_names = load_existing_test_names(REPO_ROOT, args.output_path)

    if args.preflight_only:
        report = make_empty_report(args, codex_binary)
        report["workers"] = workers
        refresh_report_summary(report, len(items))
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0

    rendered_cases: list[RenderedCase] = []
    processed_indices: set[int] = set()
    resume_in_flight_indices: list[int] = []
    report: dict[str, Any] | None = None
    resume_abort_reason = ""
    stop_controller = StopController()

    if not args.fresh:
        resumed = load_resume_state(
            args.report_file,
            inventory_by_index,
            len(items),
            args.output_path,
            args.list_path,
            args.json_path,
        )
        if resumed is not None:
            report, rendered_cases, processed_indices, resumed_names, resume_in_flight_indices = resumed
            used_names.update(resumed_names)
            resume_abort_reason = normalize_optional_string(report.get("abort_reason"))
            report["aborted"] = False
            report["abort_reason"] = ""

    if report is None:
        report = make_empty_report(args, codex_binary)
        report["workers"] = workers

    write_output_file(args.output_path, rendered_cases)
    write_report(args.report_file, report, len(items))

    items_to_process: list[InventoryItem] = []
    scheduled_indices: set[int] = set()
    for item_index in resume_in_flight_indices:
        item = inventory_by_index.get(item_index)
        if item is None:
            continue
        items_to_process.append(item)
        scheduled_indices.add(item_index)
    for item in items:
        if item.index in processed_indices or item.index in scheduled_indices:
            continue
        items_to_process.append(item)
        scheduled_indices.add(item.index)

    run_started_at = time.monotonic()
    initial_processed_count = len(report.get("processed_item_details", []))
    print(
        f"[START] {progress_summary(report, len(items), run_started_at=run_started_at, initial_processed_count=initial_processed_count)} | workers {workers} | remaining {len(items_to_process)}",
        flush=True,
    )
    print(f"[LOG] writing logs to {args.log_file}", flush=True)
    print(
        f"[CONTROL] press Ctrl+X to checkpoint and stop scheduling work. "
        f"Rerun the same command to resume from {args.report_file}.",
        flush=True,
    )
    if processed_indices or resume_in_flight_indices:
        print(
            f"[RESUME] loaded prior progress from {args.report_file} | "
            f"processed {len(processed_indices)} | requeueing {len(resume_in_flight_indices)} in-flight",
            flush=True,
        )
        if resume_abort_reason:
            print(f"[RESUME] previous stop reason: {resume_abort_reason}", flush=True)

    def handle_signal(signum: int, frame: Any) -> None:
        signal_name = signal.Signals(signum).name
        request_stop(report, stop_controller, f"{signal_name} requested stop")

    signal_numbers = [signal.SIGINT, signal.SIGTERM]
    sighup = getattr(signal, "SIGHUP", None)
    if sighup is not None:
        signal_numbers.append(sighup)
    previous_signal_handlers = {
        signum: signal.getsignal(signum) for signum in signal_numbers
    }

    try:
        for signum in signal_numbers:
            signal.signal(signum, handle_signal)

        with TtyStopWatcher(stop_controller), concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            item_iter = iter(items_to_process)
            future_map: dict[concurrent.futures.Future[AgentResult], InventoryItem] = {}

            def submit_next() -> bool:
                if stop_controller.requested:
                    report["aborted"] = True
                    if not report["abort_reason"]:
                        report["abort_reason"] = stop_controller.reason
                    return False
                if report["aborted"]:
                    return False
                next_item = next(item_iter, None)
                if next_item is None:
                    return False
                in_flight_item_indices = report.setdefault("in_flight_item_indices", [])
                if next_item.index not in in_flight_item_indices:
                    in_flight_item_indices.append(next_item.index)
                    write_report(args.report_file, report, len(items))
                future = executor.submit(
                    run_codex_with_retries,
                    next_item,
                    REPO_ROOT,
                    codex_binary,
                    args.timeout_seconds,
                    args.model,
                    args.reasoning_effort,
                    args.max_retries,
                    args.retry_backoff_seconds,
                )
                future_map[future] = next_item
                return True

            for _ in range(min(workers, len(items_to_process))):
                if not submit_next():
                    break

            while future_map:
                if stop_controller.requested:
                    report["aborted"] = True
                    if not report["abort_reason"]:
                        report["abort_reason"] = stop_controller.reason
                    write_report(args.report_file, report, len(items))
                    if stop_controller.mark_announced():
                        print(
                            f"[STOP] {report['abort_reason']} | checkpoint saved to {args.report_file} | "
                            f"waiting for {len(future_map)} in-flight workers",
                            flush=True,
                        )

                done, _ = concurrent.futures.wait(
                    future_map,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                    timeout=0.5,
                )
                if not done:
                    continue

                for future in done:
                    item = future_map.pop(future)
                    in_flight_item_indices = report.setdefault("in_flight_item_indices", [])
                    report["in_flight_item_indices"] = [
                        item_index for item_index in in_flight_item_indices if item_index != item.index
                    ]

                    try:
                        result = future.result()
                    except Exception as exc:  # pragma: no cover - one-off script
                        report["processed_item_details"].append(
                            {
                                "index": item.index,
                                "name": item.name,
                                "platform": item.platform,
                                "inventory_url": item.url,
                                "inventory_source": item.source or "same as inventory URL",
                                "status": "skipped",
                                "notes": str(exc),
                                "writeups_reviewed": [],
                                "attempts": 0,
                                "had_error": True,
                                "validation_errors": [],
                            }
                        )
                        print(
                            colorize_log_line(f"[ERROR] {item_log_label(item)} -> {exc}", ANSI_COLOR_RED),
                            flush=True,
                        )
                        write_report(args.report_file, report, len(items))
                        print(
                            f"[PROGRESS] {progress_summary(report, len(items), run_started_at=run_started_at, initial_processed_count=initial_processed_count)}",
                            flush=True,
                        )
                        if not report["aborted"]:
                            submit_next()
                        continue

                    if result.error and looks_like_quota_or_token_exhaustion(result.error) and not report["aborted"]:
                        request_stop(
                            report,
                            stop_controller,
                            (
                                f"Detected probable Codex quota/token exhaustion on "
                                f"{item_log_label(item)} after {result.attempts} attempt(s)."
                            ),
                        )
                        print(
                            colorize_log_line(f"[ABORT] {report['abort_reason']}", ANSI_COLOR_RED),
                            flush=True,
                        )

                    detail = {
                        "index": item.index,
                        "name": item.name,
                        "platform": item.platform,
                        "inventory_url": item.url,
                        "inventory_source": item.source or "same as inventory URL",
                        "writeups_reviewed": result.writeups_reviewed,
                        "notes": result.notes,
                        "attempts": result.attempts,
                        "had_error": bool(result.error),
                        "validation_errors": [],
                    }

                    if result.status != "add_cases":
                        detail["status"] = "skipped"
                        report["processed_item_details"].append(detail)
                        write_report(args.report_file, report, len(items))
                        print(
                            colorize_log_line(
                                f"[SKIP] {progress_summary(report, len(items), run_started_at=run_started_at, initial_processed_count=initial_processed_count)} | "
                                f"{item_log_label(item)} -> {result.notes}",
                                ANSI_COLOR_RED,
                            ),
                            flush=True,
                        )
                        if not report["aborted"]:
                            submit_next()
                        continue

                    newly_rendered_cases, validation_errors = validate_and_render_cases(result, used_names)
                    detail["validation_errors"] = validation_errors

                    if not newly_rendered_cases:
                        detail["status"] = "skipped"
                        report["processed_item_details"].append(detail)
                        write_report(args.report_file, report, len(items))
                        print(
                            colorize_log_line(
                                f"[REJECT] {progress_summary(report, len(items), run_started_at=run_started_at, initial_processed_count=initial_processed_count)} | "
                                f"{item_log_label(item)} -> no renderable cases",
                                ANSI_COLOR_RED,
                            ),
                            flush=True,
                        )
                        if not report["aborted"]:
                            submit_next()
                        continue

                    detail["status"] = "accepted"
                    detail["case_count"] = len(newly_rendered_cases)
                    validated_cases: list[RenderedCase] = []
                    disabled_case_details: list[dict[str, Any]] = []
                    passed_case_count = 0

                    for rendered_case in newly_rendered_cases:
                        candidate_cases = rendered_cases + validated_cases + [rendered_case]
                        write_output_file(args.output_path, candidate_cases)

                        if not args.no_validate_generated_tests:
                            validation = validate_rendered_case(
                                REPO_ROOT,
                                cargo_binary,
                                args.cargo_test_target,
                                rendered_case,
                                args.validation_timeout_seconds,
                                not args.no_validation_offline,
                            )
                            if not validation.passed:
                                rendered_case = disable_rendered_case(rendered_case, validation.reason)
                                disabled_case_details.append(
                                    {
                                        "base_name": rendered_case.base_name,
                                        "reason": rendered_case.disabled_reason,
                                        "test_names": list(rendered_case.test_names),
                                    }
                                )
                                candidate_cases = rendered_cases + validated_cases + [rendered_case]
                                write_output_file(args.output_path, candidate_cases)
                                print(
                                    colorize_log_line(
                                        f"[PARTIAL] {item_log_label(item)} -> "
                                        f"{rendered_case.base_name} disabled ({rendered_case.disabled_reason})",
                                        ANSI_COLOR_YELLOW,
                                    ),
                                    flush=True,
                                )
                            else:
                                passed_case_count += 1
                                print(
                                    colorize_log_line(
                                        f"[PASS] {item_log_label(item)} -> "
                                        f"{rendered_case.base_name} ({len(rendered_case.test_names)} tests)",
                                        ANSI_COLOR_GREEN,
                                    ),
                                    flush=True,
                                )

                        validated_cases.append(rendered_case)

                    newly_rendered_cases = validated_cases
                    detail["rendered_test_count"] = sum(len(case.test_names) for case in newly_rendered_cases)
                    detail["disabled_case_details"] = disabled_case_details

                    report["processed_item_details"].append(detail)
                    report["accepted_item_details"].append(
                        {
                            "index": item.index,
                            "name": item.name,
                            "platform": item.platform,
                            "inventory_url": item.url,
                            "inventory_source": item.source or "same as inventory URL",
                            "writeups_reviewed": result.writeups_reviewed,
                            "notes": result.notes,
                            "attempts": result.attempts,
                            "case_count": detail["case_count"],
                            "rendered_test_count": detail["rendered_test_count"],
                            "disabled_case_details": disabled_case_details,
                        }
                    )

                    for rendered_case in newly_rendered_cases:
                        rendered_cases.append(rendered_case)
                        used_names.update(rendered_case.test_names)
                        report["accepted_case_details"].append(serialize_rendered_case(rendered_case))

                    write_output_file(args.output_path, rendered_cases)
                    write_report(args.report_file, report, len(items))
                    add_color = (
                        ANSI_COLOR_GREEN
                        if not args.no_validate_generated_tests
                        and passed_case_count == detail["case_count"]
                        and detail["case_count"] > 0
                        else ANSI_COLOR_YELLOW
                    )
                    validation_summary = (
                        "validation skipped"
                        if args.no_validate_generated_tests
                        else f"passed {passed_case_count} / disabled {len(disabled_case_details)}"
                    )
                    print(
                        colorize_log_line(
                            f"[ADD] {progress_summary(report, len(items), run_started_at=run_started_at, initial_processed_count=initial_processed_count)} | "
                            f"{item_log_label(item)} -> {detail['case_count']} cases / "
                            f"{detail['rendered_test_count']} tests | {validation_summary}",
                            add_color,
                        ),
                        flush=True,
                    )
                    if not report["aborted"]:
                        submit_next()
    finally:
        for signum, previous_handler in previous_signal_handlers.items():
            signal.signal(signum, previous_handler)

    write_output_file(args.output_path, rendered_cases)
    write_report(args.report_file, report, len(items))
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if stop_controller.requested:
        return 130
    if report["aborted"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
