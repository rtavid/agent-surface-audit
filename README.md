# Agent Surface Audit

An offline CLI that inventories review-worthy risks in agent skills, MCP JSON
manifests, plugin instructions, scripts and GitHub automation before you install
or merge them.

**Status: alpha, 0.1.0.** This is a newly created project. There are no verified
adoption or download figures. Findings are heuristics for human review, not
proof of malicious intent, exploitability, or safety. No LLM or API key is needed.

## Why

An instruction file or MCP manifest can influence an agent's shell commands,
credential access and outbound requests. Reviewing only application source can
miss those surfaces. This tool puts suspicious instructions, command patterns and
manifest capabilities into one local report. It complements code review, secret
scanners and dependency auditing; it does not replace them.

## Run without installation

Python 3.10 or newer; no runtime third-party dependencies.

```console
python agent_surface_audit.py /path/to/repository
python agent_surface_audit.py /path/to/repository --format json
python agent_surface_audit.py /path/to/repository --format sarif
python agent_surface_audit.py /path/to/repository --fail-on medium
```

The CLI writes only to stdout. Redirect reports to a location **outside the target
repository**; writing a report into a scanned directory can cause it to be scanned
on a later run. Shell redirection is performed by your shell, not this program.

Optional local installation (builds require setuptools):

```console
python -m pip install .
agent-surface-audit /path/to/repository
```

No PyPI package or download count is claimed. Use this source checkout.

## What is checked

| Rule | Review signal | Severity |
| --- | --- | --- |
| EXEC001 | Remote download piped to a shell / PowerShell expression | High |
| EXEC002 | Common recursive forced deletion commands | High |
| EXEC003 | Dynamic evaluation or Python `shell=True` | Medium |
| AGENT001 | Selected instruction-override phrases | Medium |
| AGENT002 | Selected broad execution / sandbox bypass flags | High |
| CRED001 | References to selected credential locations | Medium |
| CRED002 | Selected token-like strings | High |
| CRED003 | Private-key header markers | High |
| NET001 | Selected outbound HTTP request syntax | Low |
| SUPPLY001 | Third-party GitHub Actions without full commit pins | Medium |
| SUPPLY002 | Privileged PR trigger requiring workflow review | High |
| FS001 | Parent traversal in selected file-operation syntax | Medium |
| MCP001 | `npx` MCP command without a recognized exact package version | Medium |
| MCP002 | Remote HTTP(S) MCP endpoint | Low |

See [RULES.md](RULES.md) for limitations and remediation. Remote MCP connections and
HTTP requests are ordinary capabilities; review their authorization and data flow.
Documentation quoting an attack can trigger the same rule as an actual attack.

## Reports and automation

Each finding has a rule ID, severity, surface, relative path, 1-based line, advice
and location fingerprint. Source snippets and matched token values are omitted.
For structural MCP findings the line is 1 (file-level location). Fingerprints
identify a rule/path/line/title; they change when lines move and are not content hashes.

Exit codes:

- `0`: scan completed within configured scope and no finding meets the threshold.
- `1`: completed scan has a finding at or above `--fail-on` (default: `high`).
- `2`: incomplete scan, invalid input, unreadable/oversized supported files or a
  resource limit. An empty target is incomplete. This takes priority over code 1.

`--fail-on none` disables finding-based failure, not incomplete-scan failures.
JSON exposes `complete`; SARIF exposes invocation success and scan warnings.
Neither a zero exit code nor `complete: true` means the repository is safe.

```console
python agent_surface_audit.py . --exclude test_audit.py --exclude examples --fail-on high
python -m unittest discover -v
```

The first command can still flag quoted risk examples in this documentation.
Exclusions are explicit, root-relative exact paths and descendants, not globs.
The tool does not load repository configuration or inline suppressions. The CI
workflow tests the scanner against inert fixtures rather than treating this
security documentation as malicious source.

## Scope and resource budgets

Supported text: Markdown, TXT, JSON, YAML, TOML, shell, PowerShell, batch, Python,
JavaScript, TypeScript, `.env`, Dockerfile and Makefile. UTF-8 / UTF-8 BOM only.
Other extensions and NUL-containing binary files are skipped. This is not a
complete language parser or comprehensive secret scanner.

Defaults: 512 KiB per file, 5,000 scanned files, 20 MiB total text reads and
20,000 visited directory entries. Additional fixed limits: 16,384 characters per
line and 10,000 reported findings. Files with longer lines are not inspected and
produce an incomplete report. Override the read/traversal budgets using `--max-file-bytes`, `--max-files`,
`--max-total-bytes`, `--max-entries`. Limits produce an incomplete report, not a
clean pass. Limits govern reads/traversal, not a strict CPU or wall-clock sandbox.

`.git`, dependency, build, cache and virtual-environment directories are skipped.
Symlinks and Windows reparse points are skipped. Scan an immutable checkout:
filesystem mutation races are outside the supported threat model. See
[THREAT_MODEL.md](THREAT_MODEL.md).

## Who this is for

- Maintainers reviewing third-party skill / plugin pull requests.
- Developers checking downloaded agent configuration before enabling it.
- Teams inventorying execution and network capabilities in automation repos.

## Maintenance and contributions

Contribute a minimal inert fixture, expected result and explanation of the trust
boundary. False-positive reports are as useful as new rules. Do not submit real
credentials or executable malware. Read [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md).

Initial implementation was created with Codex assistance. Maintainer review and
continued maintenance are necessary. There is no OpenAI endorsement or acceptance
into any support program implied by this project.

MIT licensed. Current roadmap: more contextual parsing, a labeled evaluation
corpus, and reviewed adapters for additional agent manifest formats. AI-assisted
issue triage and regression-fixture drafting are proposals, not shipped features.
