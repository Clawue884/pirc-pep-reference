---
name: Bug report
about: A check fails, a verdict is wrong, or behavior diverges from SPEC.md
title: "[bug] "
labels: bug
assignees: ''
---

**Which vector / scenario exposes this?**

If possible, attach the exact JSON envelope (redact keys) or name the committed attack vector.

**Expected verdict vs actual verdict**

```
expected: { ok, code, checks[] }
actual:   { ok, code, checks[] }
```

**Environment**

- Node version (`node -v`):
- OS:
- Did `npm run gen:vectors` stay green?

**Additional context**

Anything else that helps reproduce deterministically.
