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

```
IDEA       →  maintainer  →  flesh out + write ADR issue (design only, no implementation criteria)
DESIGN     →  architect   →  design the solution + write the ADR doc
           →  security    →  threat model (must sign off before code is written)
           [ADR PR reviewed and merged → ADR accepted]
                                ↓
(post-ADR) →  maintainer  →  create implementation issue(s) grounded in the settled ADR
BUILD      →  developer   →  implement against precise, ADR-grounded acceptance criteria
           →  docs        →  write docs alongside code (must be complete before PR is opened)
VERIFY     →  tester      →  verify acceptance criteria + security test cases
PR         →  security    →  final PR review
           →  docs        →  confirm docs are complete (gate on merge)
```

**Why two issues?** ADRs often change direction during review. Writing implementation acceptance criteria before the design is settled produces stale, misleading guidance. ADR issues close when the ADR PR merges; implementation issues close when the implementation PR merges.

## Starting a New Feature

Tell the maintainer agent what you want to build:

> "Use the maintainer agent — I want to add support for X"

The maintainer will ask clarifying questions, align the idea against the relevant specs, and produce an **ADR issue**. Once the architect writes the ADR, it is reviewed and merged. Only then does the maintainer create the **implementation issue** with precise acceptance criteria. From there, follow the workflow above.

## Security Issues

**Never open a public GitHub issue for a security vulnerability.**
Use GitHub's private security advisory: _Security_ → _Advisories_ → _New draft security advisory_.
