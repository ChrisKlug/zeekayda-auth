# Claim selection and token contents

**Status: provisional.** Nothing here is built — the token endpoint answers `501`. Settled in
conversation 2026-09-11 (issue #92). This sketch sits *downstream* of `claims-resolution.md`: that
seam produces the pool of subject claims, this one decides which of them land in which destination,
and what the access token's audience is. The durable constraints are in
`docs/decisions/token-issuance-and-claims.md`; read those as authoritative.

## The model in one sentence

A scope says what it unlocks in each destination; a client may add to that; the claims provider is
the only place a claim value ever comes from.

That is the IdentityServer model with the resource vocabulary removed: no identity resources, no
API resources, no API scopes as three separate registries. One `ScopeDefinition`, one claim list per
destination, and an optional audience. It is what RFC 9068 §3 describes for audience derivation,
and OIDC Core §5.4 for the standard scopes.

## Scope definition

```csharp
namespace ZeeKayDa.Auth.Scopes;

public sealed record ScopeDefinition
{
    public required string Name { get; init; }
    public bool IsDiscoverable { get; init; } = true;

    /// Claim types emitted in the ID token when this scope is granted.
    public IReadOnlyCollection<string> IdTokenClaims { get; init; } = [];

    /// Claim types returned from userinfo when this scope is granted.
    public IReadOnlyCollection<string> UserInfoClaims { get; init; } = [];

    /// Claim types emitted in the access token when this scope is granted.
    public IReadOnlyCollection<string> AccessTokenClaims { get; init; } = [];

    /// Absolute URI, no fragment, naming the resource server this scope is for. Present means "API scope".
    public string? Audience { get; init; }
}
```

Three destinations, three lists, each meaning exactly what its name says. Changes from today's
type: `IdTokenClaims` and `AccessTokenClaims` lose the `ZKD001` experimental marker,
`UserInfoClaims` and `Audience` are new. `StandardScopes` ships the OIDC Core §5.4 mapping in
*both* `IdTokenClaims` and `UserInfoClaims`, so the simple host gets its claims in the ID token;
a host that wants the spec's own default — profile claims from userinfo, a slim ID token — trims
one list:

```csharp
StandardScopes.Profile with { IdTokenClaims = ["name"] }
```

Claim type names are OIDC wire names (`given_name`, `email`), never `ClaimTypes` URIs. That is
already what `ClaimRecord.Type` carries.

## Client registration

```csharp
public interface IClientMetadata
{
    // ...existing members...

    /// Claim types added to the named selection for every grant to this client.
    IReadOnlyCollection<string> AdditionalIdTokenClaims => [];
    IReadOnlyCollection<string> AdditionalUserInfoClaims => [];
    IReadOnlyCollection<string> AdditionalAccessTokenClaims => [];
}

public sealed record ClientRegistration : IClientRegistration
{
    // ...existing members...
    public IReadOnlyCollection<string> AdditionalIdTokenClaims { get; init; } = [];
    public IReadOnlyCollection<string> AdditionalUserInfoClaims { get; init; } = [];
    public IReadOnlyCollection<string> AdditionalAccessTokenClaims { get; init; } = [];
}
```

These are **selectors, not sources**: a name here still has to come back from the claims provider
to appear anywhere. They are additive only. Subtraction is `AllowedScopes`, which already narrows
the request silently (RFC 6749 §3.3) before anything here runs. The consent page lists scopes, so
an addition is operator policy the user never sees; the guard rail is that an addition may not name
a claim any registered scope unlocks in *any* destination. A per-destination check would let
`AdditionalAccessTokenClaims = ["email"]` through, since no scope lists `email` for the access
token, and the API would read a claim the user never consented to. The guard runs per lookup,
outside `ValidatedClientResolver`'s memoised verdict: `IClientRegistrationValidator` is synchronous
and its verdict is cached by registration fingerprint, which cannot see the scope repository, so a
scope added later would leave a stale "valid". It is a set-membership test against the scope set
the authorize validator already fetches per request, so it costs no extra I/O and covers custom
repositories, not only the in-memory ones at startup. `email` can then only ever arrive through the
`email` scope and its consent; `tenant` is the operator's.

They live on `IClientMetadata` next to `AllowedScopes`, since selection runs with the token
issuer's view of the client, as default interface members returning empty — the interface's own
precedent for an optional member with a neutral default (`AllowedPromptValues`, `RequireConsent`).
Empty withholds rather than grants, so a custom repository's entity keeps compiling and the
addition is a minor version. The type matches the scope lists so a host writes `["tenant"]` in both
places; selection compares ordinally regardless of the collection, so all three join
`IClientMetadata`'s ordinal-comparison invariant, and all three join the registration fingerprint
because they change token contents.

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
            UserInfoClaims = ["customer_number"],    // fetchable from userinfo, in no token
        },
        new ScopeDefinition
        {
            Name = "orders.write",
            Audience = "https://orders.example.com/",
            AccessTokenClaims = ["role"],
        },
    ])
    .AddInMemoryClients(clients => clients.Add(
        ClientRegistration.CreateConfidential(
            "orders-web", credential, redirectUris, postLogoutRedirectUris,
            allowedScopes: ["openid", "profile", "email", "orders.read", "orders.write"]) with
        {
            AdditionalIdTokenClaims = ["tenant"],
            AdditionalAccessTokenClaims = ["tenant"],
        }));
```

A request for `openid profile orders.read` from that client yields an ID token with `sub`, the
`profile` claims and `tenant`; an access token with `role`, `tenant` and an `aud` of
`["https://orders.example.com/", "https://id.example.com"]`; and a userinfo response with `sub`,
the `profile` claims and `customer_number`. Two scopes sharing an audience string are the same API
— there is no resource entity to declare that. Scopes come from `IScopeRepository`; the in-memory
one above is the only store today, `StandardScopes` is a static template the host passes in, and
the framework is not tenant-aware — when it is, the repository is what a tenant resolves.

## Selection

Selection is an internal pure function, not an extension point. The variable part of this
subsystem is where claims come from, and that already has its seam; how they are routed is
configuration.

```csharp
internal static class ClaimSelection
{
    public static SelectedClaims Select(
        IReadOnlyList<ClaimRecord> pool,          // from IClaimsProvider, reserved names already stripped
        IReadOnlyList<ScopeDefinition> granted,   // effective scope, every name resolved against IScopeRepository
        IClientMetadata client);
}

internal sealed record SelectedClaims(
    IReadOnlyList<ClaimRecord> IdToken,
    IReadOnlyList<ClaimRecord> UserInfo,
    IReadOnlyList<ClaimRecord> AccessToken);
```

1. For each destination, the wanted types are the union of that destination's list over `granted`
   plus the client's `Additional…` list for it.
2. Each destination gets every record in `pool` whose type is wanted there. Values are the JSON the
   provider built (`claims-resolution.md`): `email_verified` is a boolean, `address` an object, and
   the issuer writes them raw. One record is written as a scalar. Repeated records for one name
   merge into one JSON array in the order returned when every value is a string, or every value is
   a number; a repeated boolean, object or array, a mix of kinds, or a repeat of a standard
   single-valued claim of OIDC Core §5.1 aborts issuance as a provider bug — merging `is_admin`
   into `[true, false]` would fail open. A provider that wants a stable array shape returns
   `ClaimValue.From(array)` once.
3. A type that is wanted but absent from the pool is simply absent from the token. Never `null`,
   never an empty string — OIDC Core §5.3.2 says an unavailable claim is omitted, and `ClaimRecord`
   refuses either at construction.
4. Protocol claims are the endpoint's, written from the grant, and are stripped from the pool before
   step 2 so a provider cannot re-assert a subject, an audience or an authentication event. The list
   is one closed constant, compared case-insensitively because a resource server's `FindFirst` is:
   `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `auth_time`, `nonce`, `acr`, `amr`, `azp`,
   `at_hash`, `c_hash`, `sid`, `scope`, `client_id`, `cnf`, `act`, and every name in the `zkd:`
   namespace. `openid` lists `sub` for readability only.

Both tokens from one issuance are selected from one pool, so they cannot disagree about a claim.

### The one change to the resolution seam

`ClaimsProviderContext` gains the union of the three wanted sets:

```csharp
public sealed record ClaimsProviderContext(
    string Sub,
    IReadOnlyList<string> Scopes,
    IReadOnlyList<string> ClaimTypes,   // what selection will keep; a hint for fetching, not a filter
    string? FamilyId);                  // null at userinfo, where there is no grant
```

Without it a provider fetching strictly by scope could never load a client-level extra. `Scopes`
stays, because a custom scope's meaning to the host ("`orders.read` implies the `role` claim
exists") is the provider's to interpret. The context is still subject-level: which client asked is
not in it, and selection — the only client-varying step — runs after the provider returns.

## Audience

The access token's `aud` is derived from the granted scopes, which is what RFC 9068 §3 says to do
when no `resource` parameter is present:

1. `audiences` = the distinct `Audience` values of the granted scopes that have one, compared
   ordinally, since RFC 7519 makes `aud` a case-sensitive string.
2. More than one distinct value is `invalid_scope`, raised by `AuthorizeRequestValidator` on the
   *effective* scope right after the `openid` check — before any interaction, before the user sees
   a page. RFC 9068 §3: "If the values in the scope parameter refer to different default resource
   indicator values, the authorization server SHOULD reject the request with invalid_scope."
   Consent and refresh can only narrow the scope, so neither can introduce a second audience; the
   token endpoint re-derives from the stored scope and treats two audiences there as `server_error`.
3. An effective scope with no `ScopeDefinition` is `invalid_scope` too: it has no audience to
   correlate to and no claims to unlock. `AllowedScopes` today is checked for blankness only, so
   the in-memory client registration gains a startup check that every allowed scope is defined,
   and the request-time rule covers custom repositories. The validator's rule table is synchronous,
   so the definitions are fetched once before the loop — one repository call per authorize request.
4. Whenever `openid` is granted, the issuer is also an audience. The userinfo endpoint is an
   OAuth 2.0 protected resource (OIDC Core §5.3) hosted by the issuer, and RFC 9068 §4 says a
   resource server MUST reject a token whose `aud` does not name it. Putting the issuer in `aud` lets
   userinfo validate as an ordinary resource server rather than carving out an exception for itself.
   `openid` is mandatory on every request today, so every access token carries the issuer.
5. Wire form follows RFC 7519 §4.1.3: a single string when there is one recipient, an array when
   there are two. `TokenPayload` serialises the value by its runtime type, so the array needs
   nothing new.
6. Every scope string in the access token's `scope` claim correlates to exactly one audience: an
   identity scope to the issuer, an API scope to its `Audience`. RFC 9068 §2.2.3 requires that the
   scope strings "MUST have meaning for the resources indicated in the aud claim", and §5 says what
   that means with more than one audience: each scope "can be unambiguously correlated to a
   specific resource among the ones listed". Step 2 is what makes it hold — with one API per token
   there is never a scope two audiences could both claim.

```json
{ "aud": "https://id.example.com" }                                        // openid profile
{ "aud": ["https://orders.example.com/", "https://id.example.com"] }       // openid orders.read
```

`Audience` must be an absolute URI without a fragment, checked by the scope startup validator
alongside the existing `openid`-presence check. RFC 8707 §2 requires both of a resource indicator
("MUST be an absolute URI", "MUST NOT include a fragment component"), and it is what makes the
`resource` parameter a pure narrowing filter when it is added later.

## Userinfo

The endpoint itself is not in the walking-skeleton milestone; only its acceptance rule is fixed
here so the audience rule above has a consumer. It is callable with `openid` alone and then answers
`sub` and nothing else; what more comes back is the `UserInfoClaims` of the granted scopes plus the
client's additions. It validates the presented access token as an RFC 9068 §4 resource server:
signature through the ring, `iss`, `exp`, `typ` of `at+jwt`, `aud` containing the issuer, and
`openid` in `scope`. It then resolves the pool fresh through `IClaimsProvider` with a `null`
`FamilyId` — never from anything stored — selects the userinfo set as above, and returns it with
`sub` (OIDC Core §5.3.2 MUST).

## Later, deliberately

- **`claims` request parameter (OIDC Core §5.5).** OPTIONAL; `claims_parameter_supported` stays
  `false`. Nothing here is shaped in a way that blocks it.
- **`resource` parameter (RFC 8707).** OPTIONAL, no discovery flag. When added, its value must equal
  the audience of a granted scope or the answer is `invalid_target`; it becomes the way a client gets
  separate tokens for two APIs out of one grant. The scope-derived default does not move.
- **`claims_supported` in discovery.** Derivable as the union of every discoverable scope's ID-token
  and userinfo claims plus the protocol claims the ID token always carries. Not decided; noted so it
  is not configured as a separate list by accident.
- **Userinfo loose ends, for the userinfo issue.** How the client is resolved for its additions
  (the token's `client_id`, presumably); what `SubjectInvalid` answers (401 `invalid_token`,
  presumably); that a provider fault is a 500 with no detail; and whether the userinfo acceptance
  rule moves into the register once the endpoint is built.
- **`IProviderSignInInteraction.SignInAsync(params Claim[])`.** With claims resolved through the
  provider, the claims that overload adds reach the session only. It may shrink to a bare
  `SignInAsync()`; that is a change to built API and is decided when the provider lands.

## Rejected

- **Per-claim destinations (OpenIddict).** Every claim routed explicitly, in code, per issuance.
  Flexible, and the thing it is best at — a claim in every token — is one line here: put it on
  `openid`, which is on every request.
- **A global "always include" list.** Same reason. `openid` is that list.
- **Identity resources, API resources and API scopes as separate registries (IdentityServer).**
  The resource entity exists to answer "who is the audience"; a string on the scope answers it.
- **One identity list feeding both the ID token and userinfo.** The first cut. It made a
  userinfo-only claim inexpressible, and the ID token rides in the client's auth cookie, so a host
  could not keep it slim. One list per destination costs the standard scopes a duplicated list
  inside `StandardScopes` and costs host code nothing.
- **A userinfo-only list on the endpoint's options.** One place, but global: it overrides the
  per-scope lists with a second mechanism and would need a merge rule, and it does not follow the
  scope repository when tenants arrive. Per scope, it comes for free.
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
- **Binding client-level additions to a granted scope.** Three reviewers asked for it, because
  consent never sees an addition. The maintainer's call is that a client-level addition is
  operator policy for simple setups; the startup guard above keeps every consent-bearing claim
  behind its scope.
