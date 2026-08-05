---
applyTo: "**"
---

For code review tasks:
- Prioritize concrete correctness and security findings over style nitpicks.
- Do not stop at style or readability. Look first for correctness bugs, security risks, spec mismatches, backward-compatibility issues, API inconsistencies, missing edge-case tests, and subtle lifecycle/concurrency problems.
- Point to exact risks, not vague concerns.
- Call out missing edge-case coverage, missing negative tests, and backward-compatibility risks.
- Flag changes that alter public API, validation semantics, trust decisions, refresh behavior, or error contracts.
- Prefer a few high-signal comments over many low-value comments.