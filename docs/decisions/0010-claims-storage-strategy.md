# ADR 0010 — Claims Resolution Strategy for Token Issuance

Status: Accepted   ·   Date: 2026-06-20   ·   Issue: #187 (see also #103, #104, #205, #206)

## Decision

Claims are **not** stored on `AuthorizationCodeEntry` or `RefreshTokenEntry` (ADR 0008). Every
issuance path — authorization code exchange and every refresh token rotation — resolves subject
claims fresh through a single mandatory interface, `IClaimsProvider`, defined in `ZeeKayDa.Auth`.
The framework never reads an identity store directly and never falls back to a cached or previous
claim set.

```csharp
namespace ZeeKayDa.Auth.Claims;

public interface IClaimsProvider
{
    Task<ClaimsResolutionResult> GetClaimsAsync(
        ClaimsProviderContext context, CancellationToken cancellationToken);
}

public sealed record ClaimsProviderContext(string Sub, IReadOnlyList<string> Scopes, string FamilyId);

public abstract class ClaimsResolutionResult
{
    private ClaimsResolutionResult() { }
    public sealed class Resolved : ClaimsResolutionResult
    { public required IReadOnlyList<ClaimRecord> Claims { get; init; } }
    public sealed class SubjectInvalid : ClaimsResolutionResult { }
}

public readonly record struct ClaimRecord(string Type, string Value);
```

`IClaimsProvider` has no default implementation and must be registered; a missing registration is a
startup `ZeeKayDaConfigurationException`, not a runtime `NullReferenceException`. A `SubjectInvalid`
result aborts issuance with `error=invalid_grant`; any exception thrown is treated as an
infrastructure failure and aborts with `error=server_error` — there is no fallback to a cached or
previous claim set on either path. Both tokens produced by a single issuance (access token and ID
token) are built from the same `GetClaimsAsync` result, so there is no split-brain where one token
reflects a claim change the other doesn't.

`ClaimsProviderContext` carries exactly `Sub`, `Scopes`, and `FamilyId` — no `ClientId` or
`GrantType`. `FamilyId` is stable across every rotation of a grant and is the natural cache key for
an implementor who wants to reduce identity-store round-trips (see Consequences); a cache miss on
`FamilyId` is structurally "first issuance," so no separate `IsRefreshRotation` flag is needed.

`ClaimRecord` (not `System.Security.Claims.Claim`) is the transfer type: `Claim` is not reliably
serialisable, carries a back-reference to `ClaimsIdentity`, and has mutable properties that have no
meaning in a resolution context.

## Why

- **Re-fetch, not snapshot.** `RefreshTokenEntry.ExpiresAt` (ADR 0008) is a *sliding* window reset on
  every rotation, with no upper bound by design. Under a snapshot model, a revoked role or disabled
  subject would never be reflected for an actively-rotating client — the exposure window is
  effectively unbounded, not merely long. Re-fetching on every issuance bounds staleness to the
  access token lifetime and makes the subject-still-valid check (`SubjectInvalid`) a natural
  consequence of the same call, rather than a second mechanism — this is how session/account
  revocation (see issues #103, #104) actually takes effect in the token pipeline.
- **A snapshot on the entry records was rejected** for exactly the unbounded-staleness reason above,
  and because it would require a *second*, separately-designed hook to get equivalent
  re-validation and claim-transformation capability — `IClaimsProvider` gives operators that hook for
  free. Operators who want snapshot-equivalent performance can still get it: an `IClaimsProvider`
  that caches by `FamilyId` with a TTL well under the access token lifetime achieves the same I/O
  profile while keeping the framework's fail-closed call-every-issuance contract intact. A
  grant-lifetime or refresh-token-lifetime TTL defeats the point and must not be used.
- **A hardcoded identity-store call in the token endpoint was rejected** as hidden I/O coupling the
  framework to a specific store API, with no seam for the host to validate, transform, or replace it.
- **An optional provider with a no-op default was rejected.** It would let a deployment silently
  issue claim-less tokens. Surfacing a missing registration at startup gives a clear, immediate
  signal instead.
- **A nullable claims list (instead of a `SubjectInvalid` case) was rejected** — it would conflate "no
  claims apply to this scope" (legitimate) with "the subject is invalid" (must abort), and an
  implementor returning `null` by mistake from the former would silently trigger the latter.
- **A separate interface (or flag) for refresh rotation vs. first issuance was rejected.** `FamilyId`
  already gives a cache-miss/cache-hit signal equivalent to "first issuance vs. rotation" without
  adding API surface that encodes an implementation assumption into the contract.
- **`ClientId` and request metadata are deliberately excluded** from `ClaimsProviderContext` — claims
  resolution is a subject-level concern; client-varying claims belong in a future claim
  transformation pipeline (deferred, see issues #205/#206), not in this seam.

## Consequences

- Every token issuance is an identity-store round trip unless the implementor caches by `FamilyId`
  with a bounded TTL — a real performance consideration for high-rotation workloads that the
  `IClaimsProvider` XML docs and getting-started samples must call out, alongside the
  `SubjectInvalid` contract (an implementation that never returns it will issue tokens for
  disabled/deleted subjects with no framework-level warning).
- Claims returned by `IClaimsProvider` may carry personal data and must never appear in log entries,
  error responses, or exception messages — `SecretSanitizingLogger` (ADR 0009) covers the
  logging-side redaction; the token endpoint itself must not embed claim values in any exception or
  error response.
- No schema change to ADR 0008's entry records, and `ClaimRecord`/`IReadOnlyList<ClaimRecord>` are
  the forward-compatible transfer types the future claim transformation pipeline will sit downstream
  of, with no breaking change to `IClaimsProvider` anticipated when that pipeline lands.
