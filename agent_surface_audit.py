"""Offline, read-only heuristics for reviewing agent and automation repositories."""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Pattern

__version__ = "0.1.0"
LEVELS = {"low": 1, "medium": 2, "high": 3}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}
EXTENSIONS = {".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".sh", ".bash",
              ".ps1", ".bat", ".cmd", ".py", ".js", ".ts", ".mjs", ".cjs", ".env"}
FILENAMES = {"Dockerfile", "dockerfile", "Makefile", ".env", ".env.example"}
MAX_LINE_LENGTH = 16384
MAX_FINDINGS = 10000


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    surface: str
    title: str
    pattern: Pattern[str]
    advice: str


def rule(id: str, severity: str, surface: str, title: str, pattern: str, advice: str) -> Rule:
    return Rule(id, severity, surface, title, re.compile(pattern, re.I), advice)


RULES = (
    rule("EXEC001", "high", "shell", "Remote download piped to an interpreter",
         r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:iwr|Invoke-WebRequest)\b[^\n|]*\|\s*(?:iex|Invoke-Expression)\b",
         "Review the source; pin and verify downloaded artifacts before execution."),
    rule("EXEC002", "high", "shell", "Recursive forced deletion",
         r"\brm\s+(?:-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*r[A-Za-z]*|--recursive\s+--force|--force\s+--recursive)\s|\bRemove-Item\b[^\n]*-Recurse\b[^\n]*-Force\b|\brd\s+/s\s+/q\b",
         "Check the resolved deletion target and require an explicit workspace boundary."),
    rule("EXEC003", "medium", "shell", "Dynamic shell evaluation",
         r"\b(?:eval|Invoke-Expression)\s*\(?|\bshell\s*=\s*True\b",
         "Trace input origins and prefer explicit argument lists to shell evaluation."),
    rule("AGENT001", "medium", "instructions", "Instruction override language",
         r"\bignore\s+(?:(?:all|the)\s+)?(?:previous|prior|system)\s+instructions\b|\b(?:bypass|disable)\s+(?:all\s+)?(?:safety|security)\s+(?:checks|restrictions|rules)\b",
         "Inspect context: this may be an attack, quotation, or defensive test; do not execute it."),
    rule("AGENT002", "high", "permissions", "Broad agent execution permission",
         r"--dangerously-skip-permissions\b|--no-sandbox\b|\bBash\(\*\)|\b(?:allow_all|allowAll)\s*[=:]\s*true\b",
         "Limit tool permissions to the task and retain approval for sensitive actions."),
    rule("CRED001", "medium", "credentials", "Reference to a sensitive credential location",
         r"(?:~|\$HOME|\$env:USERPROFILE|%USERPROFILE%)[/\\]\.(?:ssh|aws|config[/\\]gcloud)\b|\bid_(?:rsa|ed25519)\b|\bcredentials\.json\b",
         "Check whether this access is necessary and prevent credentials reaching logs or remote tools."),
    rule("CRED002", "high", "credentials", "Potential embedded service token",
         r"\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16})\b",
         "Verify privately; revoke and rotate real exposed tokens. Reports intentionally omit matched values."),
    rule("CRED003", "high", "credentials", "Private key material marker",
         r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
         "Determine whether this is a fixture or a real key; rotate real exposed keys."),
    rule("NET001", "low", "network", "Explicit outbound request capability",
         r"\b(?:curl|wget)\s+[^\n]*https?://|\b(?:requests|httpx)\.(?:get|post|put|delete|request)\s*\(|\bfetch\s*\(\s*[\"']https?://",
         "Review destinations, data sent, authentication and authorization; a request is not itself malicious."),
    rule("SUPPLY001", "medium", "supply-chain", "GitHub Action is not pinned to a full commit",
         r"\buses:\s*[\"']?[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@(?![a-f0-9]{40}(?:[\s\"'#]|$))[^\s\"'#]+",
         "Pin third-party Actions to reviewed full commit SHAs and update them deliberately."),
    rule("SUPPLY002", "high", "supply-chain", "Privileged pull request workflow trigger",
         r"\bpull_request_target\s*:",
         "Inspect checkout refs and all steps; do not execute untrusted PR code with secrets or write tokens."),
    rule("FS001", "medium", "filesystem", "Parent traversal in an explicit file operation",
         r"\b(?:open|readFile|writeFile|read_text|write_text)\s*\([^\n]*[\"'][^\"'\n]*\.\.[/\\]",
         "Resolve paths under an allowed root and reject traversal outside the workspace."),
)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    surface: str
    path: str
    line: int
    title: str
    advice: str
    fingerprint: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0

    def payload(self) -> dict:
        return {"tool": "agent-surface-audit", "version": __version__,
                "complete": not self.warnings, "files_scanned": self.files_scanned,
                "files_skipped": self.files_skipped, "warnings": self.warnings,
                "findings": [asdict(item) for item in self.findings]}


def make_finding(id: str, severity: str, surface: str, path: str, line: int,
                 title: str, advice: str) -> Finding:
    # No hash of matched source text: low-entropy secrets must not be brute-forced from a report.
    key = f"{id}\0{path}\0{line}\0{title}"
    return Finding(id, severity, surface, path, line, title, advice,
                   hashlib.sha256(key.encode("utf-8", errors="surrogatepass")).hexdigest())


def inspect_text(text: str, path: str, limit: int = MAX_FINDINGS + 1) -> list[Finding]:
    results = []
    for number, line in enumerate(text.splitlines(), 1):
        for item in RULES:
            if item.pattern.search(line):
                results.append(make_finding(item.id, item.severity, item.surface, path,
                                            number, item.title, item.advice))
        if len(results) >= limit:
            return results
    # Structural checks cover common MCP JSON manifests without loading configuration as code.
    if path.lower().endswith(".json"):
        try:
            data = json.loads(text)
        except (ValueError, RecursionError):
            return results
        if isinstance(data, dict) and isinstance(data.get("mcpServers"), dict):
            for index, server in enumerate(data["mcpServers"].values(), 1):
                if not isinstance(server, dict):
                    continue
                command, args = server.get("command"), server.get("args", [])
                if isinstance(command, str) and isinstance(args, list):
                    executable = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
                    if executable in {"npx", "npx.cmd", "npx.exe"}:
                        pinned = re.compile(r"^(?:@[^/\s]+/)?[^@/\s]+@\d+\.\d+\.\d+(?:-[\w.-]+)?$")
                        # Flags with separate values or complex npx forms are deliberately reviewable.
                        packages = [a for a in args if isinstance(a, str) and not a.startswith("-")]
                        if not packages or not pinned.fullmatch(packages[0]):
                            results.append(make_finding("MCP001", "medium", "supply-chain", path, 1,
                                f"MCP server entry {index} runs npx without a recognized exact version",
                                "Review the package and pin its exact version; a version pin is not a trust guarantee."))
                if isinstance(server.get("url"), str) and server["url"].startswith(("http://", "https://")):
                    results.append(make_finding("MCP002", "low", "network", path, 1,
                        f"MCP server entry {index} connects to a remote endpoint",
                        "Review endpoint ownership, authentication and which data and tools it receives."))
                if len(results) >= limit:
                    return results
    return sorted(results, key=lambda f: (f.path, f.line, f.rule_id, f.title))


def scan(root: Path, excludes: tuple[str, ...] = (), max_file_bytes: int = 524288,
         max_files: int = 5000, max_total_bytes: int = 20971520,
         max_entries: int = 20000) -> Report:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Scan target must be a directory")
    report = Report()
    stack, seen, total_bytes = [root], 0, 0
    excluded = tuple(value.replace("\\", "/").strip("/") for value in excludes)
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    seen += 1
                    if seen > max_entries:
                        report.warnings.append("Directory entry limit reached; scan is incomplete.")
                        return report
                    path = Path(entry.path)
                    relative = path.relative_to(root).as_posix()
                    if any(relative == value or relative.startswith(value + "/") for value in excluded):
                        report.files_skipped += 1
                        continue
                    try:
                        meta = entry.stat(follow_symlinks=False)
                        if stat.S_ISLNK(meta.st_mode) or getattr(meta, "st_file_attributes", 0) & 0x400:
                            report.files_skipped += 1
                            continue
                        if stat.S_ISDIR(meta.st_mode):
                            if entry.name not in SKIP_DIRS:
                                stack.append(path)
                            continue
                        if not stat.S_ISREG(meta.st_mode):
                            report.files_skipped += 1
                            continue
                        if path.suffix.lower() not in EXTENSIONS and path.name not in FILENAMES:
                            report.files_skipped += 1
                            continue
                        if report.files_scanned >= max_files:
                            report.warnings.append("File limit reached; scan is incomplete.")
                            return report
                        if meta.st_size > max_file_bytes:
                            report.warnings.append(f"Oversized supported file skipped: {relative}")
                            continue
                        if total_bytes + meta.st_size > max_total_bytes:
                            report.warnings.append("Total byte limit reached; scan is incomplete.")
                            return report
                        if not path.resolve(strict=True).is_relative_to(root):
                            report.warnings.append(f"Path escaped the scan root: {relative}")
                            continue
                        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                                             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
                        with os.fdopen(descriptor, "rb") as handle:
                            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                                report.warnings.append(f"File type changed while reading: {relative}")
                                continue
                            raw = handle.read(max_file_bytes + 1)
                        if len(raw) > max_file_bytes or total_bytes + len(raw) > max_total_bytes:
                            report.warnings.append(f"Read budget exceeded: {relative}")
                            return report
                        total_bytes += len(raw)
                        if b"\0" in raw:
                            report.files_skipped += 1
                            continue
                        try:
                            text = raw.decode("utf-8-sig")
                        except UnicodeDecodeError:
                            report.warnings.append(f"Non-UTF-8 supported file skipped: {relative}")
                            continue
                        report.files_scanned += 1
                        if any(len(line) > MAX_LINE_LENGTH for line in text.splitlines()):
                            report.warnings.append(f"Line exceeds 16,384 characters; file not inspected: {relative}")
                            continue
                        report.findings.extend(inspect_text(text, relative, MAX_FINDINGS - len(report.findings) + 1))
                        if len(report.findings) > MAX_FINDINGS:
                            report.findings = report.findings[:MAX_FINDINGS]
                            report.warnings.append("Finding limit reached; scan is incomplete.")
                            return report
                    except (OSError, ValueError):
                        report.warnings.append(f"Could not safely read entry: {relative}")
        except OSError:
            report.warnings.append("Could not enumerate a directory; scan is incomplete.")
    if not report.files_scanned:
        report.warnings.append("No supported UTF-8 files were scanned.")
    report.findings.sort(key=lambda f: (f.path, f.line, f.rule_id, f.title))
    report.warnings.sort()
    return report


def sarif(report: Report) -> dict:
    from urllib.parse import quote
    ids = sorted({item.rule_id for item in report.findings})
    descriptions = {item.id: item.title for item in RULES}
    descriptions.update(MCP001="Unpinned MCP package runner", MCP002="Remote MCP endpoint")
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "agent-surface-audit", "version": __version__,
                     "rules": [{"id": id, "shortDescription": {"text": descriptions[id]}} for id in ids]}},
                "invocations": [{"executionSuccessful": not report.warnings,
                    "toolExecutionNotifications": [{"level": "warning", "message": {"text": value}}
                                                   for value in report.warnings]}],
                "results": [{"ruleId": f.rule_id,
                    "level": {"high": "error", "medium": "warning", "low": "note"}[f.severity],
                    "message": {"text": f.title + ". " + f.advice},
                    "partialFingerprints": {"location/v1": f.fingerprint},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": quote(f.path, safe="/")},
                                   "region": {"startLine": f.line}}}]} for f in report.findings]}]}


def positive(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("Value must be positive")
    return number


def safe_text(value: str) -> str:
    # Escape untrusted filenames and controls instead of emitting terminal control sequences.
    return json.dumps(value, ensure_ascii=True)[1:-1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--fail-on", choices=("low", "medium", "high", "none"), default="high")
    parser.add_argument("--exclude", action="append", default=[], metavar="RELATIVE_PATH",
                        help="Skip an exact root-relative path and descendants (repeatable; no globbing)")
    parser.add_argument("--max-file-bytes", type=positive, default=524288)
    parser.add_argument("--max-files", type=positive, default=5000)
    parser.add_argument("--max-total-bytes", type=positive, default=20971520)
    parser.add_argument("--max-entries", type=positive, default=20000)
    args = parser.parse_args(argv)
    try:
        report = scan(Path(args.root), tuple(args.exclude), args.max_file_bytes,
                      args.max_files, args.max_total_bytes, args.max_entries)
    except (OSError, ValueError):
        report = Report(warnings=["Cannot scan target; supply an accessible directory."])
    if args.format == "text":
        print(f"agent-surface-audit {__version__}: {report.files_scanned} files, {len(report.findings)} findings")
        for f in report.findings:
            print(f"{safe_text(f.path)}:{f.line}: {f.severity.upper()} {f.rule_id} {f.title}")
            print(f"  {f.advice}")
        for warning in report.warnings:
            print(f"WARNING: {safe_text(warning)}")
    else:
        print(json.dumps(sarif(report) if args.format == "sarif" else report.payload(),
                         ensure_ascii=True, indent=2))
    if report.warnings:
        return 2
    return int(args.fail_on != "none" and any(
        LEVELS[f.severity] >= LEVELS[args.fail_on] for f in report.findings))


if __name__ == "__main__":
    sys.exit(main())
