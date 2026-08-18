# ADR 0006 — Exception Hierarchy Strategy

Status: Accepted   ·   Date: 2026-06-07

## Decision

All framework-thrown, non-argument exceptions derive from an abstract `ZeeKayDaException : Exception`
(in `ZeeKayDa.Auth`, root namespace) — never from a BCL semantic type such as
`InvalidOperationException`. Two concrete subtypes exist today:

- **`ZeeKayDaConfigurationException`** — setup-time misconfiguration detected lazily (a required
  value missing or invalid at the point the framework first needs it, e.g. `MapZeeKayDaAuth()`
  called before `AddZeeKayDaAuth()`). Carries one or more structured
  `ZeeKayDaConfigurationFailure(string Code, string Message)` records via
  `AggregatedFailures` — always non-empty, defensively copied. `Code` is the stable,
  semver-governed field consumers and tests switch on; `Message` is a fixed diagnostic string
  ("N configuration errors — see AggregatedFailures for details") and is never a contract.
  Most configuration errors are caught earlier by `IValidateOptions<T>`/`ValidateOnStart()`;
  this exception covers the residual runtime-only-detectable cases.
- **`ZeeKayDaInteractionException`** — request-time misuse of the interaction API (see ADR 0005's
  interaction service interfaces): no active interaction context, resuming an already-concluded
  one, wrong-step results.
- **`ZeeKayDaStoreException`** — store transport failures (see ADR 0008's exception contract for
  the authorization-code/refresh-token stores); lives in the root namespace alongside its
  siblings because store failures can occur from any store-backed feature.

```csharp
public abstract class ZeeKayDaException : Exception
{
    protected ZeeKayDaException(string message) : base(message) { }
}
public class ZeeKayDaConfigurationException : ZeeKayDaException { /* ... */ }
public class ZeeKayDaInteractionException : ZeeKayDaException { /* ... */ }
```

Both concrete subtypes are unsealed, so future releases can add finer-grained subtypes (e.g. a
future `ZeeKayDaInteractionContextExpiredException`) without breaking existing catch clauses, and
test doubles can subclass them. `ZeeKayDaException` itself is `abstract` with `protected`
constructors and no parameterless overload — it can never be thrown directly, and every throw
site must supply an actionable message. All types live in `ZeeKayDa.Auth` (core), never
`ZeeKayDa.Auth.AspNetCore`, so catching a framework exception never forces a web-stack reference
(ADR 0001's core/AspNetCore dependency layering rule extended to exceptions).

**BCL argument-guard exceptions are retained as-is** — `ArgumentNullException`, `ArgumentException`,
`ArgumentOutOfRangeException` remain correct for call-site argument validation and are never
wrapped. The dividing rule: *"you passed a bad argument to this method"* → BCL argument exception;
*"the framework is misconfigured"* or *"you used the interaction API incorrectly"* →
`ZeeKayDa*Exception`.

Naming convention: every custom exception type is `ZeeKayDa*Exception`, and lives in the
namespace of the feature it belongs to (cross-cutting types stay in the `ZeeKayDa.Auth` root;
feature-specific subtypes, once introduced, live alongside their feature's types — mirroring
`System.IO.IOException`/`System.Net.WebException`).

**Two-layer misconfiguration detection is intentional, not conflicting.** Where a config error
has both a startup-time detector (`IValidateOptions<T>`/`ValidateOnStart()`) and a request/
resolve-time fallback path, the startup validator is the primary detection layer and the
fallback path throws `ZeeKayDaConfigurationException` if the validator was bypassed or not
enabled — the two are complementary, not alternative designs.

## Why

- **Not rooted in `InvalidOperationException`**: that BCL type carries a specific, narrower
  semantic ("current object state is invalid for this operation") that doesn't fit a
  configuration or interaction-misuse error, and a `catch (InvalidOperationException)` written
  for a consumer's own code would silently swallow framework exceptions too. ASP.NET Core's own
  `AuthenticationFailureException` sets the same precedent (extends `Exception` directly).
- **A single concrete `ZeeKayDaException` with no subtypes** (rejected) — forces consumers to
  parse the message string to distinguish failure categories, which is fragile and unversioned.
- **Wrapping BCL argument exceptions in custom types** (rejected) — `ArgumentNullException` needs
  no framework-specific wrapper; doing so would diverge from every .NET convention for no benefit.
- **`ZeeKayDaException` as concrete, not abstract** (rejected) — would let framework code lazily
  throw the base type instead of the most specific available subtype.

## Consequences

Consumers get a blanket `catch (ZeeKayDaException)` handler and can still discriminate
configuration vs. interaction failures without string-parsing. The one narrow behaviour change:
code that previously caught `InvalidOperationException` from `EndpointRouteHelper.GetIssuerUri`
must now catch `ZeeKayDaConfigurationException`. Test code cannot construct the abstract base
directly — use `ZeeKayDaConfigurationException`, which is concrete. Adding a genuinely new
failure category (e.g. token issuance) requires a new subtype in a framework release; consumers
cannot add one to the hierarchy themselves.
