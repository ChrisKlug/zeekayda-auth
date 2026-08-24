---
name: write-issue
description: Write a well-structured GitHub issue for ZeeKayDa.Auth — applies the issue templates and labels, and sequences related work with blocked-by relations. Use when fleshing out a new idea, filing a bug, creating design or implementation issues, or triaging incoming issues.
argument-hint: [idea or issue description]
allowed-tools:
  - Bash(gh *)
---

# Write a GitHub Issue

This skill turns ideas, bug reports, and tasks into complete, actionable GitHub issues. It runs in the main session on purpose: issue writing depends on the conversation that led up to it.

**This project's owner is learning OSS best practices — explain the reasoning behind process choices, don't just produce artifacts.**

## Step 0 — Does this issue deserve ceremony at all?

**An issue discovered mid-work gets one line and no more.** Title, one sentence of context, a label,
`gh issue create`, done — this skill's templates do not apply to it. Full issue bodies make sideways
work feel legitimate and urgent; a one-liner is honest about what it is. The full treatment below is
for work that is deliberately being fleshed out — typically because it is about to be picked up, or
is being added to a milestone.

**Slice first.** Every issue either belongs to the current vertical-slice milestone, a later one, or
the backlog. Say which when creating it. Work is organised as vertical slices that each end in
something demonstrable — not as an undifferentiated pool of improvements.

## Step 1 — Decide the issue type

Most issues are **implementation issues** (`type:task`): one narrow, buildable thing. Write it directly.

A `type:design` issue is for a problem that is **not yet understood well enough to build** — where the issue's job is to frame the question rather than specify the work. Use it sparingly. It does *not* commit anyone to writing a design document: the shape gets agreed in conversation with the maintainer at Stage 1 of `/work-on-issue`, and lands on the issue as an `### Agreed shape` comment.

There is no ADR lifecycle any more. Do not write an issue whose deliverable is a design document, do not block implementation issues on one, and do not ask for a decision record up front — the register is written in the same PR as the change it describes, if at all.

**Uncertain?** Ask the user.

## Step 2 — Sequence it, don't nest it

There is no epic tier by default (per the workflow-leaning pivot in PR #377 — see `AGENTS.md`'s Development Workflow section). One narrow issue = one buildable thing. If this issue can't start until another one closes, record that with GitHub's native `blocked by` relation (Step 4) instead of nesting it under a coordination issue.

`type:epic` still exists as a label for the rare case of a genuinely large, multi-issue effort that needs a standing coordination point — don't create one by default, and don't feel obligated to find or attach an existing one just because the work sits in a feature area that once had one (most have since been closed/dissolved). If you're unsure whether a given piece of work warrants one, ask the user rather than defaulting to "yes."

## Step 3 — Write the issue

### Design issues (`type:design`) — the rare case

Frame the problem, not the solution:

1. Concise title in imperative sentence case ("Decide how client registration is modelled") — no implementation details, no label-like prefixes
2. **Problem statement** — what gap is being addressed
3. **Known constraints** — spec requirements, backward compatibility, security constraints
4. **Spec references** — exact spec sections any design must satisfy
5. **Open questions** — the decisions that have to be resolved before this is buildable

The issue closes when the shape is agreed and the work is done — not when a document merges.

Labels: `type:design`, relevant `area:*`, `priority:*`

### Implementation issues (`type:task`)

The default. One narrow issue = one buildable thing:

1. Concise title in imperative sentence case — no `feat:`/`fix:` prefixes, no `type:*`/`area:*`/`priority:*` tokens (classification belongs in labels)
2. **Context** — why this is needed
3. **Scope** — what is in and explicitly out of scope
4. **Acceptance criteria** — concrete and testable. Each one should name an observable behaviour someone could write a test against; "works correctly" is not a criterion
5. **Security considerations** — tag `area:security` where relevant
6. **Spec alignment** — cite the exact spec section being implemented (e.g. "per RFC 7636 §4.3"); flag conflicts with the spec before writing the issue
7. **Docs requirement** — tag `area:docs` if public-facing (user-facing docs are frozen until the walking-skeleton milestone ships; the tag marks future work, not a requirement on this PR)
8. **References** — RFC sections, related issues

Quality bar: "Could a developer implement this with no further questions?"

Labels: `type:task` (or other `type:*`), relevant `area:*`, `priority:*`

### Label taxonomy

- `area:core`, `area:aspnetcore`, `area:analyzers`, `area:docs`, `area:ci`, `area:security`, `area:extensibility`
- `type:epic`, `type:task`, `type:bug`, `type:feature`, `type:design`, `type:refactor`, `type:test`, `type:docs`, `type:chore`
- `priority:critical`, `priority:high`, `priority:medium`, `priority:low`
- `status:idea` (unscoped future work, hidden from active view), `status:needs-repro`, `status:ready`

There is deliberately no `status:blocked` label — blocked state is tracked with GitHub's native blocked-by relations (see Step 4), which resolve automatically when the blocking issue closes.
- `good first issue`, `help wanted`, `wontfix`, `duplicate`, `question`

Active work query: `is:open -label:status:idea`

## Step 4 — Blocked issues

When an issue cannot start until another issue closes, record it with GitHub's native blocked-by relation — never a `status:blocked` label, never only body prose:

```sh
# issue_id is the BLOCKING issue's databaseId
gh api graphql -f query='{ repository(owner: "OWNER", name: "REPO") { issue(number: N) { databaseId } } }'
gh api -X POST /repos/OWNER/REPO/issues/BLOCKED_NUMBER/dependencies/blocked_by -F issue_id=DATABASE_ID
```

The relation shows on both issues and resolves automatically when the blocker closes. A short body note explaining *why* it is blocked is still good practice; the relation is the machine-readable state.

### If an epic is genuinely warranted

Link a sub-issue to it with the native GitHub sub-issues API — never a text "Sub-issues" list in the epic body, never `Sub-issue of #N` lines in child bodies:

```sh
# Get the child issue's database ID
gh api graphql -f query='{ repository(owner: "OWNER", name: "REPO") { issue(number: N) { databaseId } } }'
# Link it to the parent epic
gh api -X POST /repos/OWNER/REPO/issues/PARENT_NUMBER/sub_issues --field sub_issue_id=DATABASE_ID
```

## Step 5 — Amending an issue after a decision changes

A decision made after an issue was written — a design ruling, a review finding, a maintainer call —
often invalidates part of that issue. **How you record the change depends on whether it adds or
reverses.**

- **Additive change** (a new acceptance criterion, an extra scope item, a clarification): a comment
  is fine. The body stays true; the comment extends it.
- **Reversal** (the issue asserts something the decision has since overturned): **edit the body.**
  A comment is not enough and is actively dangerous.

The failure mode is specific and it has already happened here. An issue body states the old
behaviour as a checked-off acceptance criterion. A comment further down says it was reversed. A
developer — or a subagent — works the acceptance criteria, because that is what acceptance criteria
are for, and **builds the reversed thing.** In one real case an issue instructed someone to
reimplement a feature that had been deleted three comments earlier.

When you do rewrite a body, leave a short comment saying the amendment is folded in and the body is
authoritative, so the amendment comment above it is not read as still-pending work.

### Sweep the whole set, not just the obvious issue

A ruling that reverses something usually invalidates more than one issue. After any significant
decision, scan every open issue in the affected set for:

- **Contradictions** — an acceptance criterion that now describes a bug
- **Now-vacuous criteria** — a criterion about something that no longer exists
- **Stale terminology** — a renamed type or concept, which is cosmetic but misleads a reader
- **Misplaced scope** — work reassigned to a different issue, especially deletions moved to a later
  expand/contract tail issue, which will not compile if left where it was

Grepping the bodies for the changed terms is faster and more reliable than re-reading them:

```sh
for N in $(seq FIRST LAST); do
  gh issue view $N --json body --jq .body | grep -q "OldTermName" && echo "#$N"
done
```

Distinguish legitimate references from stale ones before editing — an issue that *deletes* a type
mentions it correctly.

## Triaging incoming issues

- Apply the correct labels; identify duplicates and close with a link to the canonical issue
- Ask for reproduction steps on bug reports before accepting them
- Close stale issues with empathy — thank the reporter
- **Security reports**: escalate immediately to the private security advisory process — never a public issue
