# Architecture Decision Records

This directory holds ZeeKayDa.Auth's Architecture Decision Records (ADRs). They record
significant design decisions for contributors, not end-users. (The Jekyll site excludes this
directory; see `docs/_config.yml`.)

Every non-trivial feature follows the issue-first process described in
[`CONTRIBUTING.md`'s "Issue-First Policy"](../../CONTRIBUTING.md#issue-first-policy), which
determines when a lean ADR is warranted. This document describes the *format* an ADR file itself
should take once it exists.

## Format: lean, decision-first

An ADR records a decision worth remembering — not a design essay. Roughly half a page,
decision first:

```markdown
# ADR NNNN — <title>
Status: Accepted   ·   Date: YYYY-MM-DD   ·   Issue: #N

## Decision
<what we decided — a few sentences to a short paragraph>

## Why
<the reasoning and the key rejected alternative(s) — bullets or short prose>

## Consequences
<only if non-obvious — what changes, what to watch>
```

There are no mandatory usage/extension-sketch sections, no security banners, and no changelog
appendix. If an ADR needs amending later, rewrite the `Decision`/`Why` text in place to reflect
the current reality — don't append a dated amendment log entry underneath it. A one-line note
naming the amending issue/ADR is fine where it helps a reader find related context; a full
running history is not the goal. If an ADR runs long, it's doing too much: split the decision or
cut words.

Every decision and the key rejected alternative that led to it must survive into the lean form —
only restated spec text, narration, and ceremony get cut.

> ⚠️ **Warning: preserve security sign-off provenance.** Some ADRs carry a security-review
> approval tied to a specific commit or PR (for example, ADR 0011's `RetirementWindow`
> derivation required explicit security sign-off before merge). That sign-off record — what was
> approved, and the commit/PR it was approved against — **must be preserved**, either restated in
> the decision text if it still governs today's design, or as a one-line note pointing to it. It
> is never dropped as "just history": it is the audit trail that a specific trust-boundary
> decision was reviewed and by whom.

## Rewriting existing ADRs

Existing ADRs are being rewritten into this lean shape in small batches (see the tracking issue
for the rewrite effort) rather than left to migrate opportunistically — the earlier three-part
"current state / considered-and-rejected alternatives / changelog appendix" shape is being phased
out in favor of this one; ADRs not yet migrated (currently 0014, 0016) still use it until their
batch comes up.

## Retired numbers

Once an ADR number is retired, it is never reused for a new decision — a retired file becomes a
short stub pointing at whichever ADR absorbed its content, so an existing citation by number still
resolves to something. **ADR 0015** is retired: its content was merged into
[ADR 0011](./0011-signing-key-management.md); see [the stub](./0015-signing-provider-set-source-tiers.md).

## Why amendments are avoidable right now

Rewriting an ADR's decision in place — rather than appending an amendment that records the old
and new states side by side — is only safe because nothing outside this repository yet depends on
the old state being independently recoverable. See
[`CONTRIBUTING.md`'s "Pre-1.0 Stability Policy"](../../CONTRIBUTING.md#pre-10-stability-policy)
for why that is true today and what changes once it stops being true. That policy, not this
document, is the source of truth for *whether* in-place rewrites remain appropriate — this
document only defines the *shape* an ADR takes when they are.
