# Design sketches

Proposed API shapes for work that is **not built yet**. Contributor-facing; excluded from the
Jekyll site.

This directory exists because ZeeKayDa.Auth is a framework, not an application. Its API *is* the
product, and an API can only be judged by looking at it — the call site, the signatures, the types a
host has to name. A prose constraint like "the claims seam is mandatory" cannot be reviewed for
whether it is pleasant to use. A sketch can.

## What goes here

One file per unbuilt area. A sketch is the API as currently proposed: the host's call site written
as real code, the interfaces and records involved, and the alternatives already rejected — so the
same shape is not re-proposed and re-rejected.

## What this is not

**A sketch is not a decision in force.** It is provisional and expected to change when it meets the
real codebase. Nothing here constrains an implementer the way `docs/decisions/` does; if a sketch
and the register disagree, the register wins.

**A sketch is not user documentation.** Nothing here describes API that exists, so none of it is
publishable. When the work ships, the reference page in `docs/reference/` is written from the code.

## Lifecycle

1. A sketch is written when a design conversation settles on a shape.
2. It is revised in place as the shape changes. No amendment log — git holds that.
3. **When the work is built, the sketch is deleted.** The code becomes the record, the durable
   constraints move to `docs/decisions/`, and the usage documentation moves to `docs/reference/`.
   A sketch that outlives its implementation is stale by definition.

## Why the sketches were separated from the register

The numbered ADRs carried both, and it did not hold: they reached 4,270 lines and were amended five
times for every one written. The register replaced them and is deliberately strict — 150 lines per
file, no shapes, no design-time alternatives, "what is true now" only. That strictness is right for
a document that answers *what do I build against?*

But the ADR-to-register migration in August 2026 dropped **every** code sketch — 37 fenced blocks
across 16 ADRs, none carried forward. For built code that cost nothing: the shape is in the source.
For unbuilt design it destroyed the only record, and two accepted designs were lost outright — the
authorization endpoint's interaction model and the claims resolution seam. Both had to be recovered
from git history.

This directory is the home the register's own rules pointed at but that did not exist. The register
keeps its cap and its "drop the shape, keep the constraint" rule; the shape lands here instead of
nowhere.
