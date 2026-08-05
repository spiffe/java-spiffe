# Copilot Instructions

Repository instructions for Copilot:

- Before reviewing or suggesting edits, inspect nearby code, tests, and README files.
- Prefer minimal patches that fit the current design.
- In reviews, focus on correctness, security, spec alignment, API consistency, and missing tests.
- Do not invent repository conventions. Infer them from existing code.
- Do not suggest broad refactors unless the prompt explicitly asks for them.
- For public API changes, call out compatibility impact explicitly.
- For security-sensitive code, explain assumptions and failure modes.
- When unsure, say what is uncertain instead of guessing.

For pull request reviews:

- Lead with the highest-severity finding, and keep the review to a few high-signal comments.
- Path-specific expectations live in `.github/instructions/`. Apply the ones matching the changed files.
- Ground every finding in the actual diff, nearby code, existing tests, or the official SPIFFE standards when accessible; do not report speculative or generic issues.
- For spec-sensitive findings, cite the relevant SPIFFE standard or classify the issue as an ambiguity instead of asserting a violation.
- For each finding, state the concrete impact or failure scenario and the smallest reasonable fix, not just a theoretical risk.
- Do not invent findings to fill space. If there are no actionable issues, say so briefly instead of adding unnecessary comments or praise.
