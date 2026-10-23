# Threat model

## Assets and trust boundaries

The scanned repository is untrusted data. The scanner, Python interpreter and
operator-provided CLI arguments are trusted. Assets include the operator's files,
credentials, terminal, CI runner, and the integrity of the resulting report.

The scanner does not import scanned Python modules, execute shell commands, load
plugins, evaluate templates, follow URLs or call an LLM. It never executes or
verifies discovered credentials. JSON is decoded only as data. No source evidence
is included in output; relative paths and generic advice are included.

## Implemented protections

- Default skip list for dependency, cache and Git internals.
- Symlink and Windows reparse-point exclusion; resolved-path containment checks.
- POSIX no-follow/nonblocking flags when available; regular-file checks.
- Bounded per-file reads, total reads, scanned files and directory entries.
- Explicit incomplete reports for unreadable files and exceeded budgets.
- JSON-escaped controls in terminal paths; URI encoding of SARIF artifact paths.
- Fixed built-in rules; no executable repository configuration or automatic
  repository-controlled suppression policy.
- No runtime third-party dependencies. Packaging still has a build dependency;
  CI has third-party Actions and hosted Python dependencies.

## Limits

Scan a stable, immutable checkout. Concurrent changes can race path checks and
file opening, especially across directory replacement and on Windows. This tool
is not a filesystem sandbox. Do not scan a tree being actively mutated by an
untrusted process with access to your machine. Use an isolated container or VM for
that adversary. File metadata and filenames can themselves be sensitive. Explicit
scan roots can contain real credentials: keep resulting reports private.

Regex and JSON parsing process attacker-controlled input. Byte and entry limits
reduce resource exposure but do not impose a strict CPU/time/memory sandbox.
Nested data, huge line counts, pathological inputs, SARIF compatibility and
platform differences need ongoing testing. Findings can be false positives;
missed patterns and unsupported file formats can be false negatives.

The tool does not prove safety, enforce permission boundaries, block execution,
inspect Git history, audit installed binaries or analyze dependency vulnerability
databases. It is not antivirus, a complete secret scanner or a prompt-injection
detector with measured accuracy.

## Contributions and releases

Third-party patches can weaken rules, create unsafe reads, leak scanned content,
or change CI permissions. Review code and inert fixtures together; do not execute
contributor-provided payloads. Check dependency and workflow changes separately.
Release review must include output redaction, error exits, symlink cases and
resource-budget regressions. Do not run PR code under privileged workflow triggers.
