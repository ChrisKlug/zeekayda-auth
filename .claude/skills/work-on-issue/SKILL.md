---
name: work-on-issue
description: Drive a GitHub issue from conversation to merged PR through the project's staged loop — agree the API shape with the maintainer first, build, review locally, show the maintainer the code, then open the PR. Use whenever work starts on an issue ("can we work on issue 42", "let's do #42", "pick up 42").
argument-hint: [issue number]
allowed-tools:
  - Bash(gh *)
  - Bash(git *)
---

# Work on an issue

Six stages. **Three of them stop dead until the maintainer answers.** Those stops are the point of
this skill — they are not status updates to narrate past. Do not batch stages, do not run ahead to
"save a round trip", and do not treat your own confidence as a substitute for the maintainer's answer.

The maintainer is building a framework and is exacting about API shape. Being handed a finished PR is
the wrong moment to first see how an API reads.

| Stage | Who acts | Ends with |
|---|---|---|
| 1 · Agree the shape | `architect` + maintainer | ⛔ maintainer says "do it" |
| 2 · Build | `developer` | local commits, nothing pushed |
| 3 · Local review | `architect` / `security` | reviewers clean, findings never posted |
| 4 · Show the code | maintainer | ⛔ maintainer approves |
| 5 · PR review | `architect` / `security` | verdicts posted on the PR |
| 6 · Merge | maintainer | ⛔ maintainer approves |

---

## Stage 1 — Agree the shape ⛔

Read the issue (`gh issue view <n> --comments`) and enough surrounding code to know what already
exists.

### 1a — Name the consumers first ⛔

**Before any design work, list every call site this API will have.** Not "a consumer" in the
abstract — the actual, named ones: each blocked issue by number, each provider that implements the
contract, the DI registration, the health check, the test. Put them in a table and show it to the
maintainer in chat before proposing a shape:

| Consumer | What it needs to do |
|---|---|
| #514 JWKS endpoint | Serialise every published key to a JWK Set |
| #521 token issuer | Build a JWS header naming the key, then sign header+payload with that same key |
| third-party HSM source | Implement the source contract and register it from its own package |
| … | … |

The maintainer needs this table as much as you do: it is the shortest statement of what is being
designed for, and it is where they will spot a consumer you have not thought of. Two minutes here is
the cheapest correction in the whole loop.

**Then write each call site as code that compiles against the proposed signatures.** Not illustrative
snippets — the real call, in a scratch file, built. This is the step that catches design holes, and
skipping it is why they surface in review instead:

- A signature that reads fine in isolation but cannot express what the caller must do — a token
  issuer that has to commit a `kid` into a header *before* it can ask for a signature, say — is
  invisible until someone writes the caller's actual bytes.
- An `IDisposable` handed to a caller who will idiomatically `using` it.
- A public contract with no public way to register an implementation.
- An optional dependency that is resolved eagerly and throws when absent.

Every one of those compiles as a *description* and fails as *code*. Write the code.

If a call site cannot be written because the shape does not cover it, that is the finding — surface
it now, not in Stage 3.

### 1b — Propose the shape

Spawn **`architect`** for a *proposal*, not a document. Required, in this order:

1. Two or three sentences on what the issue actually is.
2. **The call-site table**, and each call site written as compiling code.
3. **Sample extension code** — what a third party implements. "There is no extension point" is a
   claim to check against 1a, not a shortcut: if any consumer in the table is a third-party
   implementation or a registration, there is one.
4. The one main alternative, and one line on why not.

Relay it to the maintainer in chat, code first, terse. Then iterate:

- **Structural change** (different abstraction, new extension point, moved responsibility) → a fresh
  `architect` spawn, restating the running design brief: the issue, what has been agreed so far, and
  the maintainer's latest feedback verbatim.
- **Cosmetic change** (naming, ordering, builder-vs-initializer, dropping an overload) → apply it
  yourself in chat and show the revised sample immediately. Do not spend an architect round on a name.

> `SendMessage` silently resumes an agent in the **background**, where the native LSP tool cannot
> load. Every architect round is a **fresh `Agent` call with context restated** — never a resume.

When the maintainer says "do it", post **one** comment on the issue:

```markdown
### Agreed shape

<the call-site table>

<each call site as code, against the final signatures>

<sample extension code, if there is an extension point>

Rejected: <the alternative, one line on why not>
```

That comment is the build contract and the only thing this stage puts on GitHub.

**This is a build spec, not a sketch.** `developer` runs on a smaller model and implements it
literally. Concrete signatures, types, and member names — anything left ambiguous becomes an
implementation guess. If the shape is still vague when the maintainer approves it, tighten it before
moving on.

---

## Stage 2 — Build

`developer` implements from the agreed-shape comment, on a branch off current `main`.

**Commits locally. Does not push. Does not open a PR.** Stage 4 is the maintainer's call, and a rough
first version has no business on GitHub.

---

## Stage 3 — Local review

Scope the reviewers by what the change actually touches:

| Reviewer | Runs when |
|---|---|
| `security` | tokens, crypto, endpoints, or storage |
| `architect` | public API surface, an extension point, or structure |
| neither | mechanical — bug fix, refactor, test, chore, with no API or security surface |

**Spawn the scoped reviewers in parallel, in a single message.** Neither may see the other's findings
before forming a verdict — two independent contexts are the entire value of running two reviewers,
and sequencing them destroys it.

Findings come back **to you only**. Nothing is posted to GitHub at this stage.

`developer` fixes; repeat. Stop when the reviewers are clean, or when what remains is a judgement call
that belongs to the maintainer — carry those into Stage 4 rather than deciding them yourself.

### Re-review only what changed

**The first round is a full review. Every round after it is not.** Two Opus reviewers re-reading a
whole diff to check eleven fixes is the single most expensive mistake available in this loop, and it
buys almost nothing — a reviewer re-reading from scratch mostly re-derives what it already said.

After the first round, spawn each reviewer with **its own findings and the fix commits**, and ask two
questions only: is each fix correct and complete, and did any of them introduce something worse than
it solved. That second question is not optional — this loop has produced a shutdown hang and a
half-applied dispose guard from fix rounds, and the fix round is exactly where a hardened state
machine leaves an unhardened path beside it.

A reviewer that says "I'll re-read only those" is telling you how to run the next round. Take it.

Re-run a **full** review only when the shape itself changed — a new member on a public interface, a
responsibility moved between types. Then it is a new design, and it gets a new first round.

---

## Stage 4 — Show the maintainer the code ⛔

Give them, in chat:

- the public API as it actually ended up — the real signatures, not the Stage 1 sketch;
- what changed, briefly;
- what the local review round found, and anything deliberately left unfixed and why.

The branch is local; they diff it in their own editor. Keep this short enough to actually be read —
if it is too long to read, the gate stops working.

On approval: push, then open the PR. `gh pr create` prompts for permission by design. That prompt is
this gate, enforced by the harness rather than by good intentions. Never work around it.

---

## Stage 5 — PR review

The same scoped reviewers, **again spawned in parallel in one message**, review the open PR and post
their verdicts there with `gh pr comment`. This round is the durable record.

Bring the maintainer **every** finding, with severity. Do not pre-filter to what you judged worth
fixing — the maintainer decides what gets fixed. Fixes land as commits on the same PR; reviewers
re-verify and post again.

---

## Stage 6 — Merge ⛔

On the maintainer's approval, `gh pr merge` (which prompts), then run `/post-merge-checks`.

---

## Recording decisions

Most issues touch `docs/decisions/` **not at all**. If this work changed something durable about how
the framework behaves — not a per-issue choice — add or rewrite an entry in the relevant topic file
**in the same PR**. Never a separate design PR. See `docs/decisions/README.md` for the format.

## When the loop does not apply

A genuinely mechanical change with no API or security surface — a typo, a test-only fix, a chore —
does not need six stages. Say so and just build it. Ceremony still scales with blast radius; this
skill describes the full-size path, not a minimum.
