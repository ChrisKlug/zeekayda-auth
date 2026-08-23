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
`ISigningKeyRing` and no `ISigningKeySource` — only the check itself, its options, and a
`TimeProvider` fallback. An application that adds only the health check still starts; the probe
reports `Unhealthy` naming the missing registration rather than throwing. Call
`AddZeeKayDaSigningKeySource<TSource>()` separately to give it something to report on.

**The dependency it reports on is resolved as an optional `GetService`, not `GetRequiredService`.**
`SigningKeyExpiryHealthCheck`'s constructor takes `ISigningKeyRing?`. A health check that cannot
resolve a legitimately-optional dependency must not take down the whole health report by throwing
during DI activation — `Unhealthy` is itself the correct signal for "not configured."

**The verdict logic is a pure `Evaluate` static method: no ring, no clock dependency beyond the
values passed in.** `CheckHealthAsync` is a thin adapter that resolves `CurrentOrNull`, the current
time, and the configured threshold, then calls it. This is the same shape as pulling business logic
out of a controller action, applied to `IHealthCheck.CheckHealthAsync`'s own signature, and it is why
the boundary cases (`Healthy`/`Degraded`/`Unhealthy` thresholds) are unit-testable with no DI
container and no `FakeTimeProvider` plumbing through the check itself.

**`Unhealthy` when the subsystem is absent, not `Degraded` and not silently `Healthy`.** No ring
registered, or a ring that has not yet completed startup initialization, both report `Unhealthy`
naming the reason — an unconfigured or not-yet-ready signing key ring is not a lesser form of
healthy, and an orchestrator's readiness probe must treat it as not ready.

**`Previous`/`Next` keys are reported in the result data but never drive the verdict.** Only the key
that actually signs can make the check fail; a `Previous` key past its retirement window or a `Next`
key not yet active is expected steady-state, not degradation. `SigningKeyExpiryStatus.IsSigningKey`
is compared by `Kid`, never `ReferenceEquals` — two independently-built `SigningKey` instances for
the same public key are not reference-equal, and a health check is exactly the kind of code that
builds its own `SigningKeySet` in tests.

**The `Microsoft.IdentityModel` public-surface ban does not extend to `Microsoft.Extensions.*`.**
`signing-keys.md`'s "no Microsoft.IdentityModel types on the public surface" decision is about a
large, fast-moving third-party JWT/crypto surface entering the SemVer contract by accident.
`Microsoft.Extensions.Diagnostics.HealthChecks` is a thin, stable BCL-adjacent abstraction with the
same maintenance posture as `Microsoft.Extensions.Options` or `.DependencyInjection`, already on the
public surface elsewhere in the framework — this is not the same risk and is not covered by that ban.

## Tried, didn't work

Nothing yet.
