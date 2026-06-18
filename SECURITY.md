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

## Security boundaries

ZeeKayDa.Auth includes a `SecretSanitizingLogger` that intercepts every log call made by the
library's own services and replaces known-sensitive OAuth parameters — `client_secret`,
`code_verifier`, `Authorization`, `access_token`, `refresh_token`, and others — with `[REDACTED]`
before they reach the underlying log sink.

**This redaction covers only ZeeKayDa.Auth's own internal logging.** The following log surfaces
are entirely outside the library's control and are not covered:

| Log surface | Covered? |
|---|---|
| ZeeKayDa.Auth internal structured logs | Yes |
| ASP.NET Core `UseHttpLogging()` | No |
| Kestrel connection/request logging | No |
| W3CLogger | No |
| Application Insights request telemetry | No |
| Exception-handling middleware | No |
| Your own application code calling `ILogger<T>` | No |

Consumers who rely solely on the library's internal redaction — without independently configuring
host-level log hygiene — may inadvertently write plaintext credentials (including `client_secret`
and `Authorization` header values) to their log sinks.

See the **[Configure host-level log hygiene](docs/how-to/configure-host-log-hygiene.md)** how-to
guide for concrete, copy-paste steps to:

- Prevent `UseHttpLogging()` from capturing request bodies on OAuth endpoints
- Redact the `Authorization` header in `HttpLoggingOptions`
- Suppress verbose Kestrel logs in production
- Guard exception-handling middleware against logging full request state
- Sanitize Application Insights and other telemetry SDK captured properties

## Thank You

Security researchers who responsibly disclose vulnerabilities will be credited in the release notes (unless they prefer to remain anonymous).
