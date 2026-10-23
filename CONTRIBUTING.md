# Contributing

This is an early project; no external user base or support SLA is claimed.

For a bug or new rule, provide an inert, minimal text fixture, the expected
finding (or expected absence), affected version, and why the signal is useful.
Use `example.invalid` and synthetic credentials. Never paste real tokens,
private user data, executable malware or payloads designed to run during tests.

For detection changes, add both a positive and a benign case. Include a known
limitation rather than promising complete detection. Keep checks offline,
deterministic and free of target-code execution. Any new dependency, permission,
network access or output field containing source data needs explicit review.

Run `python -m unittest discover -v` on Python 3.10 or newer. The CI matrix
covers Windows and Linux, Python 3.10 and 3.12. CI coverage is a configuration
until a public run completes; do not claim all platforms passed based on local
results alone.

Use pull requests for changes. The repository owner is the initial review contact;
maintenance and release policies can evolve with real usage. Security-sensitive
reports should follow SECURITY.md rather than public issues.
