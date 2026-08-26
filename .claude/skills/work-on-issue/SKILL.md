---
name: work-on-issue
description: Drive a GitHub issue from conversation to merged PR — talk the shape through with the maintainer in chat, build in the main session, one severity-gated review round, maintainer reads the diff, then PR and merge. Use whenever work starts on an issue ("can we work on issue 42", "let's do #42", "pick up 42").
argument-hint: [issue number]
allowed-tools:
  - Bash(gh *)
  - Bash(git *)
---

# Work on an issue

The loop: **talk the shape through in chat → build → one review round → maintainer reads the diff →
PR → merge.** Three maintainer gates (⛔): the shape, the diff, the merge.

What this loop optimises for, in order: forward progress on the current milestone, the maintainer
actually understanding and deciding things, and catching High/Critical defects before merge. What it
deliberately does **not** try to do is catch every Medium/Low finding before merge — that job belongs
to tests, the conformance suite, and the per-milestone security audit, which are better at it and
run for free forever.

**Slice check first.** Before starting, check the issue against the current milestone. Off-milestone
work is deferred, not started — say so and stop. (Exception: a genuine security hole in
already-written code.)

**And re-check it whenever scope grows.** The slice check above runs before work starts; scope that
accretes mid-build escapes it. Folding in a neighbouring issue, half of another, or an addition that
"may as well" ride along is a *recommendation with a size consequence* — state that consequence in
the same message that proposes the expansion, and propose the split when it no longer fits one
reviewable PR. Silent accretion is how a change becomes a diff too large to review well, and smaller
diffs are the only lever here that does not cost the maintainer something they value: the reviewers
stay, because they find real defects.

---

## Stage 1 — Talk the shape through ⛔

Design happens **in this conversation, with the maintainer** — never as a delivered artifact. Do not
spawn `architect` to design; that agent reviews.

Read the issue and the surrounding code, then bring the maintainer **one thing at a time**: a
signature, a call site, a question. Plain language, no assumed context — they must be able to follow
without the issue open in another window. If you catch yourself pasting a table of consumers and
three code blocks in one message, you have already failed this stage; back up and go smaller.

While converging:

- For public API, write the main call site as real code and show it — awkward APIs are caught by
  writing the caller, not by describing the callee.
- **Self-check before proposing:** does the shape contradict the issue's acceptance criteria or
  stated non-goals? Check explicitly — a wrong shape implemented faithfully is the most expensive
  error this loop has produced.
- If the work has grown past the issue, or turns out to be off-milestone, say so now.

When the maintainer says "do it", post a **short** `### Agreed shape` comment on the issue: the
signatures and the main call site, a few lines. It is a bookmark of the agreement, not a build spec —
the builder is you, and you were in the conversation.

## Stage 2 — Build

**The main session implements directly.** You have LSP, the codebase, and the design conversation in
context; there is no handoff to protect against. Commit locally, do not push, do not open a PR.

The coding standards in `.claude/agents/developer.md` apply to code you write yourself — the
"Rules that exist because review found them repeatedly" and the API self-check sections especially.
Run the suite once per change, then `/check-formatting` and `/check-code-coverage` once each.

Spawn `developer` (foreground, never background) only when the work is **large, mechanical, and fully
specified** — roughly 300+ lines of implementation logic with no open design questions. Fix rounds,
nits, and small changes are never delegated; a spawn that must re-derive context costs more than the
edit.

**New problems discovered while building get one line, not a workstream.** File a bare issue —
title, one sentence, milestone or backlog label — and move on. No `/write-issue` ceremony, no
blocked-by graphs, no design prose. Off-scope fixes are not made, however easy they look.

## Stage 3 — One review round

Scope the reviewer(s) by surface:

| Reviewer | When |
|---|---|
| `security` | tokens, crypto, endpoints, or storage |
| `architect` | public API surface, extension point, or structure |
| both (parallel, one message) | only when the change genuinely has **both** surfaces *and* exceeds ~150 lines of implementation logic |
| neither | mechanical — bug fix, refactor, test, chore |

Reviewers run **foreground**. Alongside them, run CodeScene `analyze_change_set` yourself (agents
cannot reach MCP tools) — **production files only. Findings on `tests/` are ignored entirely, not
argued with**: test code is specification, duplication is how specifications read, and clearly named
repetitive tests beat clever compact ones.

The same rule covers **every static-analysis suggestion on test files** — CodeQL included. A CodeQL
suggested fix on a test is advisory at most and is never applied via GitHub's "commit suggestion"
button: applied suggestions land as unreviewed, untested commits on the branch, and they have broken
the very tests they edited before. If a suggestion on *production* code looks right, bring it into
the working tree, run the tests, and commit it like any other change.

Then the severity gate:

- **High/Critical:** you fix them, inline, in the main session. The reviewer then verifies **the fix
  diff only** — not a fresh review of the branch.
- **Medium/Low and judgement calls:** collected into a list for Stage 4. The maintainer decides.
  There is no fix round for these and no review loop.

A fresh reviewer re-reading any code will always find something new — that is sampling noise, not a
converging process, and it is not a reason for round N+1. One round plus fix-diff verification is
the whole process. The backstops for what one round misses are the milestone audit and the
conformance suite.

**A finding that states a checkable behaviour becomes a test, not prose.** If a reviewer's finding
can be phrased as "given X, the code must Y", the fix includes a test named for it. Tests are the
durable record of security decisions; review transcripts and register paragraphs are not.

**Every commit reaches Stage 4 read by someone.** A fix commit too small for a reviewer round is
small enough for you to read yourself — and you say at Stage 4 that you, not an agent, read it.

**Every round is its own commit, and the round before it is committed first.** Commit the work, then
review it; commit the review fixes, then verify them; commit what the maintainer's rulings changed.
Never amend an earlier round's commit and never let a later round's changes ride along inside it. The
maintainer reads the branch commit by commit, so what a review found, and what their own answers
caused, must each be a diff they can read on its own — a squashed branch hides exactly the part they
asked a question about. Say in the commit message which round it came from.

## Stage 4 — Maintainer reads the diff ⛔

In chat, short enough to actually be read:

- the public API as it ended up — real signatures;
- what changed, briefly;
- High/Critical findings and how they were fixed;
- the Medium/Low list, one line each with your recommendation (fix / defer / accept);
- who read each commit.

The branch is local; the maintainer diffs it in their own editor and rules on the Medium/Lows.
Anything they want fixed, you fix inline, **as a commit of its own on top of the branch they just
read** — never folded into the commit that prompted the question. The reviewer sees the fix diff if
it touches their findings.

On approval: push, `gh pr create` (the permission prompt is this gate — never work around it), then
post each reviewer's **existing verdict** on the PR with `gh pr comment` as the durable record. That
is a paste, not a re-review. A genuine re-review happens only if commits landed after the reviewer
last looked at the branch.

## Stage 5 — Merge ⛔

On the maintainer's approval: `gh pr merge` (which prompts), then `/post-merge-checks`.

---

## Recording decisions

- **Decision register** (`docs/decisions/`): same PR as the change, rewrite in place, most changes
  touch it not at all.
- **Security sign-off entries** (`docs/decisions/security-sign-offs.md`, trust-boundary decisions
  only): written **last, once, against frozen code**, after review has concluded — never in a commit
  that is still under review. **Maximum ~15 lines.** Every claim cites its proof:
  "closed — proven by `ManualRingRegistration_IsRejected`", not a paragraph a future reviewer must
  re-probe by hand. A residual is one sentence plus a test name.
- **A fix that changes a documented rule re-checks the documents** — the register, the CHANGELOG
  entry, and the XML docs on the members involved — before the commit is made. Ask directly: did I
  just make something already written down false?

## When the loop does not apply

A mechanical change with no API or security surface — a typo, a test-only fix, a chore — is built
directly in the main session with no gates except the merge. Say so and build it.
