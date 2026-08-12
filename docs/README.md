# Documentation

API documentation lives in the code and is published on
[pkg.go.dev](https://pkg.go.dev). These pages cover what the API
reference cannot: how the repository is laid out, and why.

| Document | What it covers |
|---|---|
| [architecture.md](architecture.md) | Map of the repository: what each file and package owns, and where a new change belongs. **Start here.** |
| [writing-a-plugin.md](writing-a-plugin.md) | Building a plugin: the interfaces, the conventions, and how to test it. |
| [ai-assistant-adoption.md](ai-assistant-adoption.md) | How the project is made legible to AI coding assistants, and an honest account of what that can and cannot achieve. |

## Review records

Point-in-time audits, kept because they explain why several defences
exist. Read them newest-first for the current state, oldest-first for
the reasoning behind a particular decision.

| Document | What it covers |
|---|---|
| [release-readiness-2.md](reviews/release-readiness-2.md) | **Most recent.** Final go/no-go after the three blockers were fixed: what changed, independent re-verification, and the two environment caveats before tagging. |
| [release-readiness.md](reviews/release-readiness.md) | **Most recent.** Full test matrix, every open defect, intent-versus-delivery scoring, and a publish/do-not-publish verdict. |
| [qa-report.md](reviews/qa-report.md) | First QA and product review: the audit that found the initial defects, with before/after performance numbers. |
| [security-review-2.md](reviews/security-review-2.md) | MongoDB support, the adapter conformance suite, and a re-audit of the earlier fixes. |
| [security-review-3.md](reviews/security-review-3.md) | Empirical penetration test (fuzzing, live attacks) and the cost-optimisation pass. |

> **Note on names.** These reports were written before the packages were
> reorganised. Where they say `adapter`/`adapters/...`, read
> `storage`/`storage/...`; `sqladapter` is now `sqlstore`,
> `mongoadapter` is `mongostore`, and `adaptertest` is `storagetest`.
> References to `cors.go` and `csrf.go` are now `origin.go`, and
> `route.go` has been folded into `router.go`. The findings and
> reasoning are unchanged.
