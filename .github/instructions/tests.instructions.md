---
applyTo: "**/*test*.*,**/tests/**,**/src/test/**"
---

When editing or generating tests:
- Keep tests deterministic and readable.
- Test behavior, not implementation details, unless the repository already uses white-box tests for a good reason.
- Add focused assertions for edge cases, invalid input, refresh/update behavior, and error messages when they matter.
- Avoid brittle timing-dependent tests unless the repository already has a pattern for controlling time.