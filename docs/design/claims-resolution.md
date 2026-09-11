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

public readonly record struct ClaimRecord
{
    public ClaimRecord(string type, string value);
    public ClaimRecord(string type, bool value);
    public ClaimRecord(string type, long value);
    public ClaimRecord(string type, double value);
    public ClaimRecord(string type, JsonElement value);   // cloned on receipt; Null and Undefined throw

    public string Type { get; }
    public JsonElement Value { get; }                     // detached and immutable
}
```

`ClaimsProviderContext` carries exactly `Sub`, `Scopes`, `ClaimTypes` and `FamilyId`. `ClaimTypes`
is the union of what the downstream selection (`claim-selection.md`) will keep for this grant — a
fetching hint so a provider can load client-level additions it could not infer from `Scopes`
alone, never a filter: returning more is fine, selection drops it. `ClientId` is deliberately
absent. `FamilyId` is stable across every rotation of a grant, which makes it the natural cache key
for an implementor reducing identity-store round trips — and a cache miss on it is structurally
"first issuance".

`ClaimRecord` holds a JSON value, not an object. The constructors are the closed set of things a
claim can be: a string, a boolean, a number, or any JSON value already built — `address` is
`new ClaimRecord("address", JsonSerializer.SerializeToElement(new { formatted, country }))`. There
is no `object` overload, so `null`, a `DateTimeOffset` or a domain entity does not compile; a
`JsonElement` of kind `Null` or `Undefined` throws at construction, because an unavailable claim is
expressed by not returning the record (OIDC Core §5.3.2). The element is cloned on receipt, so
nothing the provider still holds can change a token afterwards, and `TokenPayload` writes it raw by
its runtime type with nothing left to convert. A claim name appears at most once in a result; a
multi-valued claim is one record whose value is a JSON array. A duplicate name is a provider bug and
aborts issuance as an infrastructure failure, exactly as `TokenPayload` refuses a duplicate name.

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
  the only client-varying step is selection, downstream, and it can only widen what is selected.
- **`System.Security.Claims.Claim` as the transfer type.** Not reliably serialisable, carries a
  back-reference to `ClaimsIdentity`, and has mutable properties with no meaning here.
- **A string-only claim value.** `email_verified`, `updated_at` and `address` are boolean, number
  and object on the wire, so a string value forced either a nonconforming token or claim-specific
  reconstruction inside the writer.
- **`object?` as the claim value.** Serialised by runtime type, it compiles for `null`, for a
  `DateTimeOffset` and for a domain entity, and emits a prohibited null, the wrong JSON type, or the
  entity's whole public graph respectively.
- **Merging repeated records for one name into a JSON array.** Turns two `email_verified` records
  into `[true, false]` where OIDC Core §5.1.1 requires a boolean, and `address` into an array where
  it requires an object. One record per name, with an array as the value where the claim is one.
