# Rule interpretation

All text rules operate on individual lines using fixed regular expressions.
They do not join shell continuations, parse ASTs, resolve variables, follow
imports, infer intent, or track data flow. Minified, encoded, translated,
multiline and obfuscated behavior may be missed. Quoted examples may be flagged.

## Execution: EXEC001-003

Review whether network content reaches a shell, whether deletion targets are
bounded, and whether untrusted values reach dynamic evaluation. EXEC002 covers
common combined `rm` flags and selected PowerShell/batch forms, not every syntax.
EXEC003 may flag legitimate eval-like code or defensive documentation.

## Agent instructions: AGENT001-002

Selected English override phrases and permission-bypass flags are review clues.
Prompt injection is semantic and can occur without any listed phrase. These rules
cannot certify that a skill is injection-free or enforce tool permissions.

## Credentials: CRED001-003

Path references, selected service-token shapes and private-key markers are
reported without source snippets. Placeholders can match; many real secrets do
not match. Verify privately before rotating. The scanner has no secret validity
check, network validation or Git-history scan. Reports include filenames, so do
not put secrets in filenames or assume a report is safe to publish.

## Network and files: NET001, FS001

HTTP request syntax and literal traversal in selected file calls identify review
surfaces, not unauthorized behavior. Authorization cannot be derived from these
matches. Review destination allowlists, payloads and path resolution yourself.

## Workflow supply chain: SUPPLY001-002

Action references require a full 40-character SHA to avoid SUPPLY001. A pin does
not establish that the pinned code is safe. SUPPLY002 flags a privileged PR trigger
for manual inspection even when no unsafe checkout occurs. It does not prove a
workflow exploit and does not understand all YAML forms.

## MCP manifests: MCP001-002

Only JSON objects with top-level `mcpServers` mappings receive structural checks.
For `npx` commands, the first non-option string argument must look like
`package@1.2.3` or `@scope/package@1.2.3` (optional prerelease suffix). Complex flags
with values and launchers may trigger review or be missed. Semver ranges and
`latest` trigger review. No packages are fetched or executed. Remote server URLs
are identified as capabilities; endpoint ownership and authorization need review.
Each structural finding points to line 1; its title identifies the entry ordinal.
