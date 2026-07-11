# Architecture Decision Records

This directory holds ZeeKayDa.Auth's Architecture Decision Records (ADRs). They record
significant design decisions — the problem, the chosen approach, the alternatives considered
and rejected, and the consequences — for contributors, not end-users. (The Jekyll site excludes
this directory; see `docs/_config.yml`.)

Every non-trivial feature follows the ADR-first process described in
[`CONTRIBUTING.md`'s "ADR-First Development"](../../CONTRIBUTING.md#adr-first-development).
This document describes the *format* an ADR file itself should take once it exists.

## Why this format exists

ZeeKayDa.Auth's earlier ADRs (before this document existed) recorded decisions as a top
"Decision" section followed by a chronological, ever-growing amendment log — each amendment
appended as a dated entry, some of which quietly overturned an earlier entry in the same
document. That worked while an ADR only picked up the occasional amendment, but it does not
scale: reconstructing "what's actually true today" requires mentally replaying every amendment
in order, and the top section drifts out of sync with its own amendment log over time (ADR 0011
is the motivating case — its top "Decision" section still describes an escape hatch as a `bool`
flag several amendments after that flag's type and location both changed).

Going forward, an ADR file has exactly three parts, in this order:

### 1. Current state

The decision **as it stands today**, written fresh. A reader should be able to understand the
current design completely from this section alone — no amendment-trail-tracing required. When
an ADR is amended, this section is *rewritten* to reflect the new reality, not appended to.

### 2. Considered and rejected alternatives

The reasoning trail: approaches that were considered — including ones that were tried, shipped,
and later reverted — and *why* each one was rejected or abandoned. This is where "why did we do
X, and why did we stop doing X" lives. It is a reasoning record, not a chronological diary: group
related alternatives together regardless of when they were considered, and update an entry in
place if a later amendment changes the reasoning for rejecting (or re-rejecting) something.

### 3. Changelog appendix

A **pointer-only** index: one line per change, giving the date, the PR or issue number, and a
short "what changed" summary. It exists so a reader can find *when* something changed and jump to
the relevant PR/issue for full context — it does **not** duplicate reasoning that belongs in
section 1 or 2. If a changelog entry needs more than one sentence to say what changed, the
reasoning behind it belongs in section 1 (current state) or section 2 (alternatives), and the
changelog entry should just point there.

Example shape:

```markdown
## Changelog

- 2026-07-02 — PR #286 — Escape-hatch flag became environment-list-based (`bool` → `IReadOnlyList<string>`).
- 2026-07-10 — PR #333 — Escape-hatch list moved from provider options to `AuthorizationServerOptions`.
```

> ⚠️ **Warning: preserve security sign-off provenance.** Some ADRs carry a security-review
> approval tied to a specific commit or PR (for example, ADR 0011's `RetirementWindow`
> derivation required explicit security sign-off before merge). When an ADR carrying this kind
> of provenance is migrated to this format, that sign-off record — what was approved, and the
> commit/PR it was approved against — **must be preserved** in the changelog appendix (or
> restated in the current-state section if it still governs today's design). It is never dropped
> as "just history": it is the audit trail that a specific trust-boundary decision was reviewed
> and by whom.

## Migrating existing ADRs

This format applies **immediately** to every new ADR. Existing ADRs (0001–0012 as of this
writing) are **not** rewritten in one big-bang pass just to match this format — that would be
churn for its own sake on documents that are settled and accurate.

Instead, migration is **opportunistic**: an existing ADR is rewritten into this three-part shape
the next time it is *substantively* touched anyway (a real design change, not a typo fix). ADR
0011 is the first case of this — its next substantive amendment (#337) rewrites it into this
format rather than appending amendment 9. A settled, accurate ADR that nobody needs to change is
left alone.

## Why amendments are avoidable right now

Rewriting an ADR's "current state" section in place — rather than appending an amendment that
records the old and new states side by side — is only safe because nothing outside this
repository yet depends on the old state being independently recoverable. See
[`CONTRIBUTING.md`'s "Pre-1.0 Stability Policy"](../../CONTRIBUTING.md#pre-10-stability-policy)
for why that is true today and what changes once it stops being true. That policy, not this
document, is the source of truth for *whether* in-place rewrites remain appropriate — this
document only defines the *shape* an ADR takes when they are.
