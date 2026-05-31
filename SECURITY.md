# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Public disclosure before a fix is available puts all users at risk. Please use GitHub's private security advisory feature instead:

👉 [Report a vulnerability (private)](https://github.com/ChrisKlug/zeekayda-auth/security/advisories/new)

Your report will only be visible to the maintainers until a fix has been released.

## What to Include

To help us triage and reproduce the issue quickly, please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- Affected versions (if known)
- Any suggested mitigations or fixes you may have

## Disclosure SLA

| Milestone | Target |
|---|---|
| Acknowledgement | Within **2 business days** of receipt |
| Fix or mitigation | Within **90 days** of acknowledgement |

If we cannot meet the 90-day target, we will notify you and agree on an extended timeline before public disclosure.

## Automated Security Scanning

This project runs [GitHub CodeQL](https://codeql.github.com/) static analysis on every pull request, every push to `main`, and on a weekly schedule. The `security-and-quality` query suite is used. All CodeQL findings are treated as bugs — they must be fixed or explicitly justified before a PR is merged. Results are visible in the [Security → Code Scanning](https://github.com/ChrisKlug/zeekayda-auth/security/code-scanning) tab.

## Scope

This policy covers the `ZeeKayDa.Auth` and `ZeeKayDa.Auth.AspNetCore` NuGet packages. Issues in third-party dependencies should be reported upstream.

## Thank You

Security researchers who responsibly disclose vulnerabilities will be credited in the release notes (unless they prefer to remain anonymous).
