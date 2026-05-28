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
IDEA     →  maintainer  →  flesh out + write GitHub issue
DESIGN   →  architect   →  design the solution + ADR
         →  security    →  threat model (must sign off before code is written)
BUILD    →  developer   →  implement
         →  docs        →  write docs alongside code (must be complete before PR is opened)
VERIFY   →  tester      →  verify acceptance criteria + security test cases
PR       →  security    →  final PR review
         →  docs        →  confirm docs are complete (gate on merge)
```

## Starting a New Feature

Tell the maintainer agent what you want to build:

> "Use the maintainer agent — I want to add support for X"

The maintainer will ask clarifying questions, align the idea against the relevant specs, and produce a GitHub issue. From there, follow the workflow above.

## Security Issues

**Never open a public GitHub issue for a security vulnerability.**
Use GitHub's private security advisory: _Security_ → _Advisories_ → _New draft security advisory_.
