# Claims resolution

**Status: provisional.** Nothing here is built — the token endpoint answers `501`. Recovered from
ADR 0010 (accepted 2026-06-20, issue #187), which was deleted in the register migration.
The constraints this design produced survived and are in
`docs/decisions/token-issuance-and-claims.md` — read those as authoritative. What follows is only
the shape, plus the alternatives already rejected. What is selected from the result, and
into which token, is `claim-selection.md`.

## The seam

Claims are never stored on `AuthorizationCodeEntry` or `RefreshTokenEntry`, and never read from the
session. Every issuance path — authorization code exchange and every refresh rotation — resolves
subject claims fresh through one mandatory interface, and so does userinfo.

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
    string? FamilyId);                   // null where there is no grant to key on: userinfo

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
    // The one place that validates: a null or empty string, NaN or infinity, a JSON null from
    // From, or a default ClaimValue is refused here, and the message names the type, never the value.
    public ClaimRecord(string type, ClaimValue value);

    public string Type { get; }
    public ClaimValue Value { get; }
}

public readonly record struct ClaimValue                             // conversions never throw
{
    public static implicit operator ClaimValue(string value);
    public static implicit operator ClaimValue(bool value);
    public static implicit operator ClaimValue(int value);
    public static implicit operator ClaimValue(long value);
    public static implicit operator ClaimValue(double value);
    public static implicit operator ClaimValue(AddressClaim value);
    public static ClaimValue From<T>(T value, JsonSerializerOptions? options = null) where T : notnull;
}

public sealed record AddressClaim                                    // OIDC Core §5.1.1, wire names built in
{
    public string? Formatted { get; init; }
    public string? StreetAddress { get; init; }
    public string? Locality { get; init; }
    public string? Region { get; init; }
    public string? PostalCode { get; init; }
    public string? Country { get; init; }
}
```

What a provider writes:

```csharp
new ClaimRecord("name", "Chris"),
new ClaimRecord("email_verified", true),
new ClaimRecord("updated_at", user.UpdatedAt.ToUnixTimeSeconds()),
new ClaimRecord("address", new AddressClaim { Formatted = "...", Country = "SE" }),
new ClaimRecord("role", "admin"), new ClaimRecord("role", "editor"),   // → "role": ["admin", "editor"]
new ClaimRecord("tenant", ClaimValue.From(tenantInfo)),                // custom shape, deliberate
```

`ClaimsProviderContext` carries exactly `Sub`, `Scopes`, `ClaimTypes` and `FamilyId`. `ClaimTypes`
is the union of what the downstream selection (`claim-selection.md`) will keep for this grant — a
fetching hint so a provider can load client-level additions it could not infer from `Scopes`
alone, never a filter: returning more is fine, selection drops it. `ClientId` is deliberately
absent. `FamilyId` is stable across every rotation of a grant, which makes it the natural cache key
for an implementor reducing identity-store round trips — and a cache miss on it is structurally
"first issuance". It is `null` at userinfo, which is a read with no grant behind it. A cache key
therefore always includes `Sub`: the family id is never a key on its own, so a `?? ""` fallback can
never collapse every userinfo call into one slot that serves one subject's claims to another.

`ClaimValue` is a JSON value, not an object. The implicit conversions cover every type a standard
claim can be, and none of them throws — Framework Design Guidelines §5.7 — so the one place that
validates is `ClaimRecord`'s constructor, which refuses a null or empty string, NaN or infinity, a
JSON null and a default `ClaimValue`, naming the claim type and never the value. `AddressClaim`
covers the one standard object claim; its conversion writes the OIDC Core §5.1.1 member names
itself (`street_address`, `postal_code`, …), omits null members, and never passes through `From`.
A custom object goes through `From`, which serialises it right there — with the options given, or
snake_case by default, OIDC's own convention — once, so a custom object reaches a token only by a
deliberate call, never by being handed over. The record holds the resulting JSON detached from
anything the provider keeps, so nothing mutated afterwards can change a token, and `TokenPayload`
writes it raw. An unavailable claim is expressed by not returning the record (OIDC Core §5.3.2).
A struct is still default-constructible, so `default(ClaimRecord)` is guarded the way
`TokenIssuanceContext` guards it: the members throw, and selection treats one in a result as a
provider bug.

A provider returns one record per value, and one record is written as a scalar. Three `role`
records become `"role": ["admin", "editor", "viewer"]` on the wire, in the order returned and never
deduplicated: RFC 7519 §4 requires unique claim names, and that array is exactly what the ASP.NET
Core JWT handler turns back into three `role` claims on the consuming side. Merging is for strings,
or for numbers, all of one kind. A repeated boolean, object or array, a mix of kinds, or a repeat
of a standard single-valued claim (OIDC Core §5.1) is a provider bug and aborts issuance as an
infrastructure failure, exactly as `TokenPayload` refuses a duplicate name — `is_admin` merged into
`[true, false]` would fail open on a consumer's `HasClaim`. A provider that wants an array shape
regardless of count returns `ClaimValue.From(array)` once.

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
- **Claims taken from the session principal at issuance.** The same staleness as a snapshot, with
  the cookie as the snapshot; and the collect-more page would become a second claims path.
- **A string-only claim value.** `email_verified`, `updated_at` and `address` are boolean, number
  and object on the wire, so a string value forced either a nonconforming token or claim-specific
  reconstruction inside the writer.
- **`object?` as the claim value.** Serialised by runtime type, it compiles for `null`, for a
  `DateTimeOffset` and for a domain entity, and emits a prohibited null, the wrong JSON type, or the
  entity's whole public graph respectively.
- **A serializer call at the provider's call site.** `JsonSerializer.SerializeToElement` for every
  address is hostile to the person writing the provider; the conversions on `ClaimValue` and a
  typed `AddressClaim` cover every standard claim without one.
- **Refusing repeated records for one name.** A provider looping over roles is the normal case, and
  the array is what the JWT handler on the other side expects. The refusal applies to repeats of a
  boolean, object or array, to mixed kinds, and to the standard single-valued claims — where a
  repeat cannot be anything but a bug, and where merging would fail open.
- **Validation inside the implicit conversions.** Guidelines say an implicit cast must not throw,
  and the failure would name `op_Implicit` and no claim. The record's constructor validates instead
  and names the type.
