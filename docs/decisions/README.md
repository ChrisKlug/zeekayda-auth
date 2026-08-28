# Decision register

What is true **now** about how ZeeKayDa.Auth works, and what we tried that didn't work. One file
per topic area. Contributor-facing, not end-user documentation — the Jekyll site excludes this
directory (see `docs/_config.yml`).

This is not a history. It answers two questions for whoever reads it next: *what do I build
against?* and *what shouldn't I re-propose?*

## Format

Two sections. Nothing else.

```markdown
# Signing keys

## Decisions in force

**Keys come from a provider, not configuration.** `ISigningKeyProvider` returns a key set; the
framework picks the active key. Providers ship as separate NuGet packages.

## Tried, didn't work

- **macOS Keychain provider.** Built and reviewed, then descoped — nobody hosts a production auth
  server on macOS, and the file-system provider already covers it.
```

- **No numbers, no `Status`, no `Date`, no issue or PR references, no changelog, no amendment log.**
- A decision changed? **Rewrite the entry in place.** Git holds the history; nobody reads a
  superseded decision on purpose.
- A decision was abandoned? Move it to *Tried, didn't work* with one line on why.
- Entries are written **in the same PR as the change they describe** — never a separate design PR.
- Most changes touch this directory not at all. It records durable framework behaviour, not a log
  of what was decided this week.

## Keep it short

**Files are capped at 150 lines, enforced by CI.** At the cap, cut words or split the topic —
never raise the cap.

The cap exists because the previous format didn't hold. These files used to be numbered ADRs;
they reached 4,270 lines across 14 documents, were amended roughly five times for every one
written, and grew to 1,297 lines despite a written "half a page" target. Guidance didn't
constrain it, so now the build does.

The same restraint applies to *Tried, didn't work*. An entry earns its place if **we built it, or
a reviewer signed off on it, before it was reversed** — those are the mistakes worth the tokens to
prevent twice. Design-time "we considered X and didn't do it" is noise; leave it out.

## What doesn't belong here

- **API reference** — interface listings, type shapes, contract tables, worked examples. Those go
  in `docs/reference/` for built API, and `docs/design/` for API that isn't built yet. If an entry is
  explaining *how to use* something rather than *what we settled on*, it's in the wrong directory.
- **Rationale essays.** State the decision and enough of the why to stop someone reversing it by
  accident. If it needs three paragraphs, write a `docs/explanation/` page and keep the entry short.
- **Speculative API shapes for work that isn't built.** A proposed interface name, signature, or
  record shape for code that does not exist is not a decision in force — it is a sketch, and it will
  be redone against the real codebase when the work is picked up. Carrying it here anchors whoever
  builds it on stale thinking.

  What *does* belong, for unbuilt work: decisions already realised in shipped code, security or
  correctness properties, spec-mandated refusals, and rejected alternatives someone would otherwise
  re-propose. Those are true now — they constrain what exists — so they read correctly as decisions
  in force. **Drop the shape, keep the constraint.**

  **The shape goes to `docs/design/`, not nowhere.** This is a framework: the API is the product, and
  a shape can only be judged by looking at it. Dropping sketches on the floor is how two accepted
  designs were lost in the ADR migration and had to be recovered from git. A sketch there is
  explicitly provisional, is deleted when the work ships, and never overrides this register.

## The one exception: security sign-offs

`security-sign-offs.md` is exempt from the format and the line cap. Security approvals tied to a
specific commit or PR are an audit trail — the record that a particular trust-boundary decision was
reviewed, by whom, against what, and with which residual risks explicitly accepted. That is
inherently dated and inherently historical, and it is never dropped as "just history."

Everywhere else, keep history out.
