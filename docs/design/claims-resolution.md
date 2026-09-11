# Claims resolution

**Status: provisional.** Nothing here is built — the token endpoint answers `501`. Recovered from
ADR 0010 (accepted 2026-06-20, issue #187), which was deleted in the register migration.
The constraints this design produced survived and are in
`docs/decisions/token-issuance-and-claims.md` — read those as authoritative. What follows is only
the shape, plus the alternatives already rejected. What is selected from the result, and
into which token, is `claim-selection.md`.

## The seam

Claims are never stored on `AuthorizationCodeEntry` or `RefreshTokenEntry`. Every issuance path —
authorization code exchange and every refresh rotation — resolves subject claims fresh through one
mandatory interface.

```csharp
namespace ZeeKayDa.Auth.Claims;

public interface IClaimsProvider
{
    Task<ClaimsResolutionResult> GetClaimsAsync(
        ClaimsProviderContext context, CancellationToken cancellationToken);
}

public sealed record ClaimsProviderContext(
    string Sub,
    IReadOnlyList<string> Scopes,
    IReadOnlyList<string> ClaimTypes,
    string FamilyId);

public abstract class ClaimsResolutionResult
{
    private ClaimsResolutionResult() { }

    public sealed class Resolved : ClaimsResolutionResult
    {
        public required IReadOnlyList<ClaimRecord> Claims { get; init; }
    }

    public sealed class SubjectInvalid : ClaimsResolutionResult { }
}

public readonly record struct ClaimRecord(string Type, object? Value);
```

`ClaimsProviderContext` carries exactly `Sub`, `Scopes`, `ClaimTypes` and `FamilyId`. `ClaimTypes`
is the union of what the downstream selection (`claim-selection.md`) will keep for this grant — a
fetching hint so a provider can load client-level additions it could not infer from `Scopes`
alone, never a filter: returning more is fine, selection drops it. It was added 2026-09-11
(issue #92); `ClientId` is still deliberately absent. `FamilyId` is stable across
every rotation of a grant, which makes it the natural cache key for an implementor reducing
identity-store round trips — and a cache miss on it is structurally "first issuance".

`ClaimRecord.Value` is `object?`, serialised by its runtime type under the same rule as
`TokenPayload`: a provider returns `email_verified` as a `bool`, `updated_at` as a `long`, and
`address` as an object carrying the OIDC Core §5.1.1 member names — never as pre-encoded strings.
Repeated records for one type are written as one JSON array under that name, in the order returned.
(Changed 2026-09-11, issue #92: the original `string Value` could not represent the standard
boolean, number and object claims.)

## Rejected

- **Snapshotting claims onto the stored entry records.** A refresh token's expiry is a sliding window
  with no upper bound, so a revoked role or disabled subject would never reach an actively-rotating
  client — the staleness window is unbounded, not merely long. It would also need a second,
  separately-designed hook to get equivalent re-validation and transformation.
- **A hardcoded identity-store call in the token endpoint.** Hidden I/O, coupling the framework to
  one store's API with no seam to validate, transform or replace it.
- **An optional provider with a no-op default.** Lets a deployment silently issue claim-less tokens.
  A missing registration is a startup failure instead.
- **A nullable claims list instead of a `SubjectInvalid` case.** Conflates "no claims apply to this
  scope" (legitimate) with "this subject must not receive tokens" (must abort), and an implementor
  returning `null` by mistake from the former silently triggers the latter.
- **A separate interface or flag for refresh rotation versus first issuance.** `FamilyId` already
  gives that signal without encoding an implementation assumption into the contract.
- **`ClientId` and request metadata on the context.** Claims resolution is a subject-level concern;
  client-varying claims belong in a downstream transformation pipeline.
- **`System.Security.Claims.Claim` as the transfer type.** Not reliably serialisable, carries a
  back-reference to `ClaimsIdentity`, and has mutable properties with no meaning here.
- **A string-only claim value.** The original `ClaimRecord` shape. `email_verified`, `updated_at`
  and `address` are boolean, number and object on the wire, so a string value forced either a
  nonconforming token or claim-specific reconstruction inside the writer.
