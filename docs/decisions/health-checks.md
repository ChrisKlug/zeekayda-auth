# Health checks

The framework's first `Microsoft.Extensions.Diagnostics.HealthChecks` integration
(`SigningKeyExpiryHealthCheck`) and the pattern it sets for any that follow.

## Decisions in force

**Registered on `IHealthChecksBuilder`, never on `IServiceCollection` directly.** A health check is
opt-in per application, added via its own `Add<Check>()` extension on the host's own
`AddHealthChecks()` builder — never wired automatically by `AddZeeKayDaAuthCore()` or any signing
registration. Health reporting and signing configuration are independent decisions an operator makes
separately.

**A health check never registers the thing it reports on.** `AddZeeKayDaSigningKeys()` registers no
`SigningKeyRing` and no `ISigningKeySource` — only the check itself, its options, and a
`TimeProvider` fallback. An application that adds only the health check still starts; the probe
reports `Unhealthy` naming the missing registration rather than throwing. Call
`builder.AddSigningKeySource<TSource>()` (or a provider's own method) separately to give it something to report on.

**The dependency it reports on is resolved as an optional `GetService`, not `GetRequiredService`.**
`SigningKeyExpiryHealthCheck`'s constructor takes `SigningKeyRing?`. A health check that cannot
resolve a legitimately-optional dependency must not take down the whole health report by throwing
during DI activation — `Unhealthy` is itself the correct signal for "not configured."

**The verdict logic is a pure `Evaluate` static method: no ring, no clock dependency beyond the
values passed in.** `CheckHealthAsync` is a thin adapter that resolves `CurrentOrNull`, the ring's
timeline and failed successor, the current time, and the configured threshold, then calls it. This is the same shape as pulling business logic
out of a controller action, applied to `IHealthCheck.CheckHealthAsync`'s own signature, and it is why
the boundary cases (`Healthy`/`Degraded`/`Unhealthy` thresholds) are unit-testable with no DI
container and no `FakeTimeProvider` plumbing through the check itself.

**`Unhealthy` when the subsystem is absent, not `Degraded` and not silently `Healthy`.** No ring
registered, or a ring that has not yet completed startup initialization, both report `Unhealthy`
naming the reason — an unconfigured or not-yet-ready signing key ring is not a lesser form of
healthy, and an orchestrator's readiness probe must treat it as not ready.

**The signing-key verdict asks the ring's own rules, never its own reading of the keys.**
`Unhealthy` when the key signing now has expired; `Degraded`, naming every reason, when a successor's
signer failed and was set aside, when a listed key was dropped (its failure codes only — a
source id may be a path or vault URI, and the description may be public), when the key due now is not the key signing (a handover still
running), or when `SigningKeyTimeline.At(now + DegradedThreshold)` has no unexpired key to sign
with; otherwise `Healthy`. A staged successor that
will take over in time therefore keeps the check `Healthy`, and the check and the ring cannot
disagree about which key signs. Every published key is reported in the result data;
`SigningKeyExpiryStatus.IsSigningKey` is compared by `Kid`, never `ReferenceEquals`.

**The `Microsoft.IdentityModel` public-surface ban does not extend to `Microsoft.Extensions.*`.**
`signing-keys.md`'s "no Microsoft.IdentityModel types on the public surface" decision is about a
large, fast-moving third-party JWT/crypto surface entering the SemVer contract by accident.
`Microsoft.Extensions.Diagnostics.HealthChecks` is a thin, stable BCL-adjacent abstraction with the
same maintenance posture as `Microsoft.Extensions.Options` or `.DependencyInjection`, already on the
public surface elsewhere in the framework — this is not the same risk and is not covered by that ban.

## Tried, didn't work

- **A verdict that predicted the successor from the key set** (a newer key past the lead time before the
  signing key's expiry, and "restart to rotate" once one was). It duplicated the ring's choice and needed a
  fix for every rule it missed; asking the ring's timeline replaced it.
