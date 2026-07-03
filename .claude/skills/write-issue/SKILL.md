---
name: write-issue
description: Write a well-structured GitHub issue for ZeeKayDa.Auth — decides between an ADR issue and an implementation issue, applies the issue templates, hierarchy, and labels, and links sub-issues to their epic. Use when fleshing out a new idea, filing a bug, creating design or implementation issues, or triaging incoming issues.
argument-hint: [idea or issue description]
allowed-tools:
  - Bash(gh *)
---

# Write a GitHub Issue

This skill turns ideas, bug reports, and tasks into complete, actionable GitHub issues. It runs in the main session on purpose: issue writing depends on the conversation that led up to it.

**This project's owner is learning OSS best practices — explain the reasoning behind process choices, don't just produce artifacts.**

## Step 1 — Decide the issue type

**Does this work need an ADR?** An ADR is warranted for non-obvious decisions with lasting consequences: new abstractions, storage contracts, public API shape, security-sensitive designs, or anything where "why did we choose this?" will matter in 6 months.

Routine work does **not** need an ADR: adding a property to an existing model, fixing a bug, implementing something fully prescribed by the spec, or adding tests.

- **ADR needed** → write an *ADR issue* (design phase). Never write the implementation issues yet — they come after the ADR PR merges.
- **No ADR needed** → write an *implementation issue* directly.
- **Uncertain** → ask the user before deciding.

Never write an ADR issue until the problem is fully understood — ask clarifying questions first.

## Step 2 — Identify or create the parent epic

Every `type:design` and `type:task` issue must be a sub-issue of a `type:epic`. If no epic exists for the feature area, create one first (title prefix: `Epic: `). Epics are permanent coordination points, closed only when all sub-issues are closed — confirm with the user before closing one.

## Step 3 — Write the issue

### ADR issues (`type:design`)

Frame the problem, not the solution:

1. Concise title in imperative sentence case ("Design client registration model") — no implementation details, no label-like prefixes
2. **Problem statement** — what gap is being addressed, why it needs an ADR
3. **Known constraints** — spec requirements, backward compatibility, security constraints
4. **Spec references** — exact spec sections the design must satisfy
5. **Open design questions** — the decisions the ADR must resolve (the architect's agenda)
6. **Sign-off criteria** — what the ADR must answer; the issue closes when the ADR PR merges
7. **Security flag** — note if tokens/crypto/protocol flows are involved; security must sign off on the ADR PR

Quality bar: "Does this give the architect a clear agenda and unambiguous sign-off criteria?"

Labels: `type:design`, relevant `area:*`, `priority:*`

### Implementation issues (`type:task`)

Written only after the ADR PR merges (for ADR-path work):

1. Concise title in imperative sentence case — no `feat:`/`fix:` prefixes, no `type:*`/`area:*`/`priority:*` tokens (classification belongs in labels)
2. **Context** — why this is needed; link the accepted ADR
3. **Scope** — what is in and explicitly out of scope
4. **Acceptance criteria** — concrete, testable conditions derived from the ADR, not speculative
5. **Security considerations** — tag `area:security` where relevant
6. **Spec alignment** — cite the exact spec section being implemented (e.g. "per RFC 7636 §4.3"); flag conflicts with the spec before writing the issue
7. **Docs requirement** — tag `area:docs` if public-facing
8. **References** — ADR link, RFC sections, related issues
9. End with: "The docs agent must be involved — documentation is required for all public-facing changes"

Quality bar: "Could a developer implement this with no further questions?"

Labels: `type:task` (or other `type:*`), relevant `area:*`, `priority:*`

### Label taxonomy

- `area:core`, `area:aspnetcore`, `area:analyzers`, `area:docs`, `area:ci`, `area:security`, `area:extensibility`
- `type:epic`, `type:task`, `type:bug`, `type:feature`, `type:design`, `type:refactor`, `type:test`, `type:docs`, `type:chore`
- `priority:critical`, `priority:high`, `priority:normal`, `priority:low`
- `status:idea` (unscoped future work, hidden from active view), `status:needs-repro`, `status:blocked`, `status:ready`
- `good first issue`, `help wanted`, `wontfix`, `duplicate`, `question`

Active work query: `is:open -label:status:idea`

## Step 4 — Link the sub-issue to its epic

Always use the native GitHub sub-issues API — never a text "Sub-issues" list in the epic body, never `Sub-issue of #N` lines in child bodies:

```sh
# Get the child issue's database ID
gh api graphql -f query='{ repository(owner: "OWNER", name: "REPO") { issue(number: N) { databaseId } } }'
# Link it to the parent epic
gh api -X POST /repos/OWNER/REPO/issues/PARENT_NUMBER/sub_issues --field sub_issue_id=DATABASE_ID
```

Do this immediately after creating any issue that belongs to an epic. Sub-issue ordering reflects execution sequence — design before tasks, foundational tasks before dependent ones.

## Triaging incoming issues

- Apply the correct labels; identify duplicates and close with a link to the canonical issue
- Ask for reproduction steps on bug reports before accepting them
- Close stale issues with empathy — thank the reporter
- **Security reports**: escalate immediately to the private security advisory process — never a public issue
