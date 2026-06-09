# ZeeKayDa.Auth — Agent Team

This repository uses a team of specialised Copilot agents. Use `/agent` in Copilot CLI to select one, or reference an agent by name in your prompt.

## The Team

| Agent | Invoke as | Role |
|---|---|---|
| **maintainer** | `use the maintainer agent` | OSS project setup, issue writing, triaging, release management |
| **architect** | `use the architect agent` | Technical direction, API design, Architecture Decision Records |
| **developer** | `use the developer agent` | Feature implementation, bug fixes, code quality |
| **security** | `use the security agent` | Threat modelling, security review, OAuth/OIDC compliance |
| **tester** | `use the tester agent` | Test strategy, test implementation, coverage |
| **docs** | `use the docs agent` | All user-facing documentation (Jekyll/Markdown) |

## Feature Development Workflow

Issues follow a three-tier hierarchy: **epics** (`type:epic`) → **design issues** (`type:design`) → **task issues** (`type:task`). Every design and task issue must be a sub-issue of its parent epic. Sub-issues are ordered to reflect execution sequence.

```
IDEA       →  maintainer  →  identify or create the parent epic (type:epic)
                              then write a design issue (type:design) as a sub-issue of the epic
                              (or a task issue directly if no ADR is needed)
DESIGN     →  architect   →  design the solution + write the ADR doc
           →  security    →  threat model (must sign off before code is written)
           [ADR PR reviewed and merged → ADR accepted]
                                ↓
(post-ADR) →  maintainer  →  create task issue(s) (type:task) grounded in the settled ADR,
                              as sub-issues of the parent epic
BUILD      →  developer   →  implement against precise, ADR-grounded acceptance criteria
           →  docs        →  write docs alongside code (must be complete before PR is opened)
VERIFY     →  tester      →  verify acceptance criteria + security test cases
PR         →  security    →  final PR review
           →  docs        →  confirm docs are complete (gate on merge)
```

**Why the three-tier model?** ADRs often change direction during review. Writing implementation acceptance criteria before the design is settled produces stale, misleading guidance. Epics keep the full lifecycle of a feature area visible in one place; design issues close when their ADR PR merges; task issues close when their implementation PR merges.

**`status:idea`** marks epics, design issues, and tasks for future ideas not yet ready for design or implementation. Active work query: `is:open -label:status:idea`.

## Starting a New Feature

Tell the maintainer agent what you want to build:

> "Use the maintainer agent — I want to add support for X"

The maintainer will ask clarifying questions, align the idea against the relevant specs, identify or create the parent epic, and produce a **design issue**. Once the architect writes the ADR, it is reviewed and merged. Only then does the maintainer create the **task issue(s)** with precise acceptance criteria. From there, follow the workflow above.

## Security Issues

**Never open a public GitHub issue for a security vulnerability.**
Use GitHub's private security advisory: _Security_ → _Advisories_ → _New draft security advisory_.
