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

## Redirect URI validation

ZeeKayDa.Auth enforces exact-ordinal string matching for redirect URI comparisons, as required by
[RFC 9700 §2.1](https://www.rfc-editor.org/rfc/rfc9700#section-2.1). Two behaviours operators
must be aware of:

### No normalisation

The framework performs **no normalisation** before comparing a request's `redirect_uri` against a
client's registered URIs. The comparison is always against the exact string that was registered.

This means:

- `https://app/cb` does **not** match `https://app/cb/` — trailing slash matters
- `https://app/cb%20x` does **not** match `https://app/cb x` — percent-encoding is not decoded
  before comparison

Operators must register the exact URI the client will send on the wire. If a client sends
`https://app/cb` in its authorization request, `https://app/cb/` must not be registered in its
place.

> ⚠️ **Warning:** Normalisation gaps are a common source of redirect URI bypass vulnerabilities.
> Registering a URI with an unintended trailing slash or a different percent-encoding form from
> what the client sends can cause legitimate requests to be rejected. Test the exact wire form
> your client sends against what is registered.

### Loopback port exception

For redirect URIs whose host is a loopback address (`127.0.0.1` or `[::1]`), the port component
is ignored during comparison. This is the one intentional deviation from exact-match, required by
[RFC 8252 §7.3](https://www.rfc-editor.org/rfc/rfc8252#section-7.3) because loopback ports are
OS-assigned and cannot be fixed at registration time. All other URI components are still matched
exactly.

### Private-use URI scheme heuristic

The scheme allowlist for registered redirect URIs permits any scheme that contains a `.` character,
as an approximation of [RFC 8252 §7.1](https://www.rfc-editor.org/rfc/rfc8252#section-7.1)'s
reverse-DNS guidance for private-use schemes in native applications (for example,
`com.example.myapp:/callback`).

This heuristic is **approximate**: it accepts any scheme containing a `.` that is not `https` or
`http`, regardless of whether it follows the full `tld.org.app` reverse-DNS shape. It does not
validate that the scheme is actually owned by the registering party or that it conforms to the
RFC 8252 §7.1 naming convention.

> ⚠️ **Warning:** Because scheme validation is approximate, human review of private-use scheme
> registrations is still expected. CI or automated registration pipelines should not treat
> framework acceptance as a substitute for confirming that a private-use scheme is genuinely
> controlled by the registering party. An attacker who can register a client on a shared platform
> could claim an arbitrary dotted scheme.

## Thank You

Security researchers who responsibly disclose vulnerabilities will be credited in the release notes (unless they prefer to remain anonymous).
