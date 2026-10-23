# Security policy

Version 0.1.x is alpha. No independent security audit or supported response SLA is
claimed. Use an isolated environment when processing hostile material.

Report a suspected scanner vulnerability using the repository's private security
advisory reporting option if enabled. If it is unavailable, open a public issue
requesting a private contact **without** exploit details, secrets or sensitive
paths. Do not assume a private channel has already been configured.

Useful reports identify the trust boundary, affected version, inert reproduction
and observed impact. Credential leakage, reads outside the scan root, unexpected
execution or network access, report/terminal injection and resource exhaustion
are relevant. A missed heuristic alone is usually a detection improvement;
document it without calling it a verified exploit.

Do not publish live credentials or another project's unpatched vulnerability in
an issue here. Report upstream vulnerabilities to the responsible project.
