# Claim selection and token contents

**Status: provisional.** Nothing here is built — the token endpoint answers `501`. Settled in
conversation 2026-09-11 (issue #92). This sketch sits *downstream* of `claims-resolution.md`: that
seam produces the pool of subject claims, this one decides which of them land in which token, and
what the access token's audience is. The durable constraints are in
`docs/decisions/token-issuance-and-claims.md`; read those as authoritative.

## The model in one sentence

A scope says what it unlocks in each token; a client may add to that; the claims provider is the
only place a claim value ever comes from.

That is the IdentityServer model with the resource vocabulary removed: no identity resources, no
API resources, no API scopes as three separate registries. One `ScopeDefinition`, two claim lists,
and an optional audience. It is what RFC 9068 §3 describes for audience derivation, and OIDC Core
§5.4 for the standard scopes.

## Scope definition

```csharp
namespace ZeeKayDa.Auth.Scopes;

public sealed record ScopeDefinition
{
    public required string Name { get; init; }
    public bool IsDiscoverable { get; init; } = true;

    /// Claim types emitted in the ID token and returned from userinfo when this scope is granted.
    public IReadOnlyCollection<string> IdentityClaims { get; init; } = [];

    /// Claim types emitted in the access token when this scope is granted.
    public IReadOnlyCollection<string> AccessTokenClaims { get; init; } = [];

    /// Absolute URI naming the resource server this scope is for. Present means "API scope".
    public string? Audience { get; init; }
}
```

Changes from today's type: `IdTokenClaims` becomes `IdentityClaims`, because the same list feeds
userinfo; both lists lose the `ZKD001` experimental marker; `Audience` is new. `StandardScopes`
keeps the OIDC Core §5.4 mapping it has now, with no audience on any identity scope.

Claim type names are OIDC wire names (`given_name`, `email`), never `ClaimTypes` URIs. That is
already what `ClaimRecord.Type` carries.

## Client registration

```csharp
public sealed record ClientRegistration : IClientRegistration
{
    // ...existing members...

    /// Claim types added to the identity selection for every grant to this client.
    public IReadOnlySet<string> AdditionalIdentityClaims { get; init; } = new HashSet<string>(StringComparer.Ordinal);

    /// Claim types added to the access-token selection for every grant to this client.
    public IReadOnlySet<string> AdditionalAccessTokenClaims { get; init; } = new HashSet<string>(StringComparer.Ordinal);
}
```

These are **selectors, not sources**: a name here still has to come back from the claims provider
to appear anywhere. They are additive only. Subtraction is `AllowedScopes`, which already narrows
the request silently (RFC 6749 §3.3) before anything here runs. Both land on `IClientMetadata`
next to `AllowedScopes`, since selection runs with the token issuer's view of the client; that
interface is third-party-implementable, so the addition is a breaking change and is made pre-1.0.

## Host call site

```csharp
builder.Services
    .AddZeeKayDaAuth(o => o.Issuer = "https://id.example.com")
    .AddInMemoryScopes(
    [
        .. StandardScopes.All,
        new ScopeDefinition
        {
            Name = "orders.read",
            Audience = "https://orders.example.com/",
            AccessTokenClaims = ["role"],
        },
        new ScopeDefinition
        {
            Name = "orders.write",
            Audience = "https://orders.example.com/",
            AccessTokenClaims = ["role"],
        },
    ])
    .AddInMemoryClients(
    [
        ClientRegistration.CreateConfidential(
            "orders-web", credential, redirectUris, postLogoutRedirectUris,
            allowedScopes: ["openid", "profile", "email", "orders.read", "orders.write"]) with
        {
            AdditionalIdentityClaims = new HashSet<string>(StringComparer.Ordinal) { "tenant" },
            AdditionalAccessTokenClaims = new HashSet<string>(StringComparer.Ordinal) { "tenant" },
        },
    ]);
```

A request for `openid profile orders.read` from that client yields an ID token with `sub`, the
`profile` claims and `tenant`; an access token with `role`, `tenant` and an `aud` of
`["https://orders.example.com/", "https://id.example.com"]`; and a userinfo response equal to the
ID token's subject claims. Two scopes sharing an audience string are the same API — there is no
resource entity to declare that.

## Selection

Selection is an internal pure function, not an extension point. The variable part of this
subsystem is where claims come from, and that already has its seam; how they are routed is
configuration.

```csharp
internal static class ClaimSelection
{
    public static SelectedClaims Select(
        IReadOnlyList<ClaimRecord> pool,          // from IClaimsProvider, reserved names already stripped
        IReadOnlyList<ScopeDefinition> granted,   // effective scope, resolved against IScopeRepository
        IClientMetadata client);
}

internal sealed record SelectedClaims(
    IReadOnlyList<ClaimRecord> Identity,          // ID token and userinfo
    IReadOnlyList<ClaimRecord> AccessToken);
```

1. `identityTypes` = union of `IdentityClaims` over `granted`, plus `client.AdditionalIdentityClaims`.
   `accessTypes` likewise from `AccessTokenClaims` and `AdditionalAccessTokenClaims`.
2. `Identity` = every record in `pool` whose type is in `identityTypes`; `AccessToken` the same over
   `accessTypes`. Multi-valued claims keep every record. Order is the provider's.
3. A type that is selected but absent from the pool is simply absent from the token. Never `null`,
   never an empty string — OIDC Core §5.3.2 says an unavailable claim is omitted.
4. Protocol claims (`iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, `scope`, `client_id`,
   `jti`, and the rest of the reserved list) are the endpoint's, written from the grant. They are
   stripped from the pool before step 2 exactly as they are stripped from the host's principal, so a
   provider cannot re-assert a subject or an audience. `openid` lists `sub` for readability only.

Both tokens from one issuance are selected from one pool, so they cannot disagree about a claim.

### The one change to the resolution seam

`ClaimsProviderContext` gains the union of `identityTypes` and `accessTypes`:

```csharp
public sealed record ClaimsProviderContext(
    string Sub,
    IReadOnlyList<string> Scopes,
    IReadOnlyList<string> ClaimTypes,   // what selection will keep; a hint for fetching, not a filter
    string FamilyId);
```

Without it a provider fetching strictly by scope could never load a client-level extra. `Scopes`
stays, because a custom scope's meaning to the host ("`orders.read` implies the `role` claim
exists") is the provider's to interpret. The context is still subject-level: which client asked is
not in it, and selection — the only client-varying step — runs after the provider returns.

## Audience

The access token's `aud` is derived from the granted scopes, which is what RFC 9068 §3 says to do
when no `resource` parameter is present:

1. `audiences` = the distinct `Audience` values of the granted scopes that have one.
2. More than one distinct value is `invalid_scope`, raised by `AuthorizeRequestValidator` on the
   *effective* scope right after the `openid` check — before any interaction, before the user sees
   a page. RFC 9068 §3: "If the values in the scope parameter refer to different default resource
   indicator values, the authorization server SHOULD reject the request with invalid_scope."
   Consent and refresh can only narrow the scope, so neither can introduce a second audience; the
   token endpoint re-derives from the stored scope and treats two audiences there as `server_error`.
3. Whenever `openid` is granted, the issuer is also an audience. The userinfo endpoint is an
   OAuth 2.0 protected resource (OIDC Core §5.3) hosted by the issuer, and RFC 9068 §4 says a
   resource server MUST reject a token whose `aud` does not name it. Putting the issuer in `aud` lets
   userinfo validate as an ordinary resource server rather than carving out an exception for itself.
   `openid` is mandatory on every request today, so every access token carries the issuer.
4. Wire form follows RFC 7519 §4.1.3: a single string when there is one recipient, an array when
   there are two. `TokenPayload` serialises the value by its runtime type, so the array needs
   nothing new.

```json
{ "aud": "https://id.example.com" }                                        // openid profile
{ "aud": ["https://orders.example.com/", "https://id.example.com"] }       // openid orders.read
```

`Audience` must be an absolute URI, checked by the scope startup validator alongside the existing
`openid`-presence check. RFC 8707 requires that of a resource indicator, and it is what makes the
`resource` parameter a pure narrowing filter when it is added later.

## Userinfo

The endpoint itself is not in the walking-skeleton milestone; only its acceptance rule is fixed
here so the audience rule above has a consumer. It validates the presented access token as an
RFC 9068 §4 resource server: signature through the ring, `iss`, `exp`, `typ` of `at+jwt`, `aud`
containing the issuer, and `openid` in `scope`. It then resolves the pool fresh through
`IClaimsProvider` — never from anything stored — selects the identity set as above, and returns it
with `sub` (OIDC Core §5.3.2 MUST). Putting identity claims in both the ID token and userinfo is
spec-clean: §5.4 routes the standard scopes' claims to userinfo, and §2 says the ID token "MAY
contain other Claims".

## Later, deliberately

- **`claims` request parameter (OIDC Core §5.5).** OPTIONAL; `claims_parameter_supported` stays
  `false`. Nothing here is shaped in a way that blocks it.
- **`resource` parameter (RFC 8707).** OPTIONAL, no discovery flag. When added, its value must equal
  the audience of a granted scope or the answer is `invalid_target`; it becomes the way a client gets
  separate tokens for two APIs out of one grant. The scope-derived default does not move.
- **`claims_supported` in discovery.** Derivable as the union of every discoverable scope's identity
  claims plus the protocol claims the ID token always carries. Not decided; noted so it is not
  configured as a separate list by accident.

## Rejected

- **Per-claim destinations (OpenIddict).** Every claim routed explicitly, in code, per issuance.
  Flexible, and the thing it is best at — a claim in every token — is one line here: put it on
  `openid`, which is on every request.
- **A global "always include" list.** Same reason. `openid` is that list.
- **Identity resources, API resources and API scopes as separate registries (IdentityServer).**
  The resource entity exists to answer "who is the audience"; a string on the scope answers it.
- **No `aud` when no API scope is requested.** IdentityServer's behaviour. RFC 9068 §2.2 makes `aud`
  REQUIRED and §3 makes a default resource indicator a MUST. The issuer is the default.
- **Userinfo ignoring `aud` and checking only the `openid` scope.** Also IdentityServer's behaviour,
  and it does satisfy OIDC Core; it needs our own endpoint to be the one resource server that does
  not apply RFC 9068 §4 to itself. Issuer-in-`aud` satisfies every text at once and costs a URL.
- **A switch to drop the issuer from `aud`.** The `EmitStaticAudienceClaim` shape. A toggle that
  makes our own userinfo endpoint reject our own tokens is a supported misconfiguration.
- **Multiple API audiences in one token.** Allowed by RFC 8707 with `resource`, discouraged by it,
  and without `resource` there is nothing to disambiguate with. One grant, one API, until `resource`
  lands.
- **Selection as a public seam.** A host that wants different routing changes scope or client
  configuration. Opening the function would let a third party route a claim the provider never
  returned, or move a protocol claim, and the house pattern is a public seam for the variable part
  and a closed one for the protocol.
- **Client-level claim removal.** `AllowedScopes` already subtracts, at the granularity the client
  consented to. A second subtractive list is a second place to look when a claim goes missing.
