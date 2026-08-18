# ADR 0007 — Client Registration Model

Status: Accepted   ·   Date: 2026-06-07

## Decision

Clients are statically registered (RFC 7591 dynamic registration is deferred to a future,
decorator-based `ZeeKayDa.Auth.DynamicClients` package — see Why). The model is an interface,
not a sealed shape, so a custom `IClientRepository` can make its own entity types implement it
directly with no mapping allocation on the hot path:

```csharp
namespace ZeeKayDa.Auth.Clients;

public interface IClientRegistration
{
    string ClientId { get; }
    IReadOnlyList<IClientCredential> Credentials { get; }   // empty = public client
    bool IsPublic { get; }                                   // declared, not derived — see below
    IReadOnlySet<string> RedirectUris { get; }
    IReadOnlySet<string> PostLogoutRedirectUris { get; }
    IReadOnlySet<string> AllowedScopes { get; }
    IReadOnlySet<GrantType> AllowedGrantTypes { get; }
    IReadOnlySet<ResponseType> AllowedResponseTypes { get; }
    IReadOnlySet<ResponseMode> AllowedResponseModes { get; }
    IReadOnlySet<string> AllowedTokenEndpointAuthMethods { get; }
    IReadOnlySet<PromptValue> AllowedPromptValues { get; }
    bool EnableZkdErrorCodes { get; }
    IReadOnlySet<SigningAlgorithm>? AllowedSigningAlgorithms => null; // DIM: null = inherit server default
}
```

`ClientRegistration` (`ZeeKayDa.Auth`) is the framework's sealed-record implementation; validation
lives in `IClientRegistrationValidator`, not the constructor, so tests can build invalid instances.

**Enum vs. string per vocabulary**: `GrantType`/`ResponseType`/`ResponseMode`/`PromptValue` are
enums (a new value needs framework code anyway). `AllowedTokenEndpointAuthMethods` is
`IReadOnlySet<string>` because `IClientAuthenticator` is a genuine open extension point — a
custom `tls_client_auth` authenticator must be expressible without a framework release. All
`IReadOnlySet<string>` members MUST be enumerated with explicit `StringComparer.Ordinal` by every
consumer — the set's own comparer is not trusted, since a custom repository's entity type might
construct it with `OrdinalIgnoreCase`.

**Credential model — type identity is the algorithm, not a string discriminator:**

```csharp
public interface IClientCredential { }
public interface IClientSecret : IClientCredential { }
public interface IPbkdf2ClientSecret : IClientSecret { int Iterations { get; } byte[] Salt { get; } byte[] Hash { get; } }
public sealed record Pbkdf2ClientSecret(int Iterations, byte[] Salt, byte[] Hash) : IPbkdf2ClientSecret;
```

Rejected: `string? ClientSecret` (ambiguous plaintext-vs-hash, pushes fixed-time comparison to
every implementer) and a single `string Algorithm` discriminator with nullable per-algorithm
fields (central switch statement, grows unboundedly). A consumer adding bcrypt defines
`IBCryptClientSecret : IClientSecret` and a paired `ClientSecretHasher<IBCryptClientSecret>` —
no framework change needed. `IClientSecretHasher.Verify` always uses
`CryptographicOperations.FixedTimeEquals` and never throws (`false` on internal error). The
shipped `Pbkdf2ClientSecretHasher` default is PBKDF2-HMAC-SHA256, 600,000 iterations minimum
(current OWASP guidance), enforced both at creation (constructor) and at import time
(`IClientSecretHasher.GetRegistrationFailures`, since a pre-hashed credential migrated from
another IdP bypasses the constructor). At most two active shared-secret credentials per client
are permitted, to support rotation; authenticators try all of them before failing.

`CompositeClientSecretHasher` routes each credential to the hasher that `CanHandle`s it and pads
verification failures to a fixed two-credential timing budget, so a client mid-rotation is not
timing-distinguishable from an unknown client. Public clients (the `none` auth path) are the one
accepted residual: `none` is intrinsically faster than any secret verification and padding it
would impose a flat ~600ms cost on the most common production request — accepted, with rate
limiting as the primary mitigation (RFC 9700 §2.1).

**`IClientAuthenticator` — self-describing dispatch, no method-specific composite logic:**

```csharp
public interface IClientAuthenticator
{
    IReadOnlySet<string> AuthenticationMethods { get; }             // for startup coverage validation
    bool CanHandle(TokenRequestContext context, out string? method); // cheap shape check only
    ValueTask<ClientAuthenticationResult> AuthenticateAsync(ClientAuthenticationContext context, CancellationToken ct);
}
```

The composite (`CompositeClientAuthenticator`) has zero method-specific knowledge — it never
special-cases `client_secret_basic` vs. `tls_client_auth`; each authenticator declares what it
handles and detects it. `none` is the one reserved case: it's the composite's fallback after
every credential-bearing authenticator declines, never a `CanHandle` participant, because a
generic "no evidence" authenticator can't know about every custom mechanism (a `tls_client_auth`
authenticator might legitimately claim the request while a naive public-client authenticator also
claims `none`, producing a false multi-mechanism rejection). Extending to a new method (e.g. mTLS)
requires no composite change: implement `IClientAuthenticator`, register it, add the method
string to `TokenEndpointOptions.AuthMethodsSupported`. Startup validation requires every
advertised server method to have exactly one owning authenticator; `none` must never be declared
by any authenticator.

**Redirect URI validation** — exact ordinal string match; no prefix/normalisation/wildcard
matching; `http://` accepted only for loopback (port variable per RFC 8252 §7.3); fragments and
userinfo rejected; scheme is a **pure allowlist** (`https` any host, `http` loopback only, any
private-use scheme containing a `.` per RFC 8252 §7.1) — no blocklist is maintained, since every
dangerous scheme (`javascript`, `data`, `file`, …) already lacks a dot and is rejected by the
allowlist alone. `localhost` gets an advisory `LogWarning` (RFC 8252 §8.3) recommending the IP
literal; the loopback test is a whole-string match, never substring, so `localhost.attacker.com`
correctly fails. Same rules apply to `PostLogoutRedirectUris`.

**`IClientRepository`** — one async lookup method:

```csharp
public interface IClientRepository
{
    ValueTask<IClientRegistration?> FindByClientIdAsync(string clientId, CancellationToken ct = default);
}
```

Returns `null` (never throws) for unknown or malformed `client_id` — throwing would change
timing and leak information usable for client-ID enumeration. `InMemoryClientRepository`
validates every registration at construction via `IClientRegistrationValidator` and throws
`ZeeKayDaConfigurationException` before the host starts accepting requests; custom repositories
must resolve and call the same validator at write time (or first read, for read-mostly stores) —
a companion analyzer (`ZEEKAYDA0003`) flags out-of-assembly implementations that never reference
it, because several of the invariants it enforces (PBKDF2 iteration floor, two-secret cap,
`IsPublic` consistency, allowlist subset checks) have **no runtime twin** — a repository that
skips validation can silently persist a registration that violates them.

**Consistency invariant** (enforced at registration): `IsPublic == true ⇔ Credentials.Count == 0
⇔ AllowedTokenEndpointAuthMethods == { "none" }`. `IsPublic` is declared on the interface rather
than derived via a default interface method, deliberately — a silent DIM default would let a
configuration omission silently change security-relevant behaviour instead of failing the
startup consistency check. No per-client `RequirePkce` flag exists — OAuth 2.1 §7.6 mandates
PKCE unconditionally, with no opt-out.

**Scope intersection**: `effective_scopes = (requested ∩ client.AllowedScopes) ∩
user_granted_scopes`; dropped scopes are silently omitted from the request and never echoed in
error responses; `IConsentInteraction.GrantAsync` (see ADR 0005's consent interaction interface)
re-intersects as a last line of defence so a host bug can't grant scopes the client was never
registered for.

**Client enumeration mitigation**: `invalid_client` for both unknown `client_id` and wrong
credential, with `error_description` never including the `client_id`; when `EnableZkdErrorCodes`
is on, the `zkd_error` value must never distinguish the two cases either. Logs MUST never include
presented client secrets, raw `Authorization` headers, raw token endpoint request bodies
containing `client_secret`, or `code_verifier` values (RFC 7636 §7.5).

**Package split**: `IClientRegistration`, `ClientRegistration`, credential/hasher types,
`IClientRepository`/`InMemoryClientRepository`, `IClientRegistrationValidator`, and the
per-client vocabularies all live in `ZeeKayDa.Auth` (core, no request context needed).
`IClientAuthenticator` and its context types are request-aware and live in
`ZeeKayDa.Auth.AspNetCore`.

## Why

- **Interface, not sealed record, as the primary shape** — lets custom repositories return their
  own ORM-mapped entity types directly. A discriminated-union return (separate public/confidential
  types) was considered and rejected: added complexity without a proportionate safety gain given
  the declared `IsPublic` and its startup consistency check.
- **`IReadOnlyDictionary<string, IClientRegistration>` as the repository shape** (rejected) —
  forces full in-memory materialisation, no async I/O, leaks enumeration.
- **A `CanHandle(context)`-only extension point with no static `AuthenticationMethods` declaration**
  (rejected) — startup coverage validation would need synthetic HTTP requests to know what an
  authenticator supports.
- **Composite-side request-shape sniffing** (rejected during review) — an earlier draft hard-coded
  "Basic header → `client_secret_basic`" in the composite; that defeats the extension point, since
  adding `tls_client_auth` would require modifying the composite itself.
- **A three-valued `Valid`/`NotValid`/`NoResult` outcome** (rejected) — was needed for a
  chain-of-responsibility dispatch; `CanHandle` filtering the candidate set first collapses this
  to a binary `Authenticated` flag, since at most one authenticator ever runs per request.
- **Dynamic client registration (RFC 7591) in v1** (deferred) — materially increases attack
  surface for a static-first framework; the v1 abstractions are shaped to be decorator-compatible
  with a future write-side package without breaking changes.
- **Single `TokenEndpointAuthMethod` enum retained for discovery** (rejected, amends ADR
  0002/0003) — kept separate from `AllowedTokenEndpointAuthMethods`, the discovery document
  couldn't advertise a custom method a host adds via `IClientAuthenticator`. Strings now carry
  the vocabulary end-to-end; `TokenEndpointOptions.AuthMethodsSupported` is the operator's global
  allowlist and the only source discovery reads from.

## Consequences

Custom repositories bypass registration-time validation unless they explicitly call
`IClientRegistrationValidator`; the analyzer is a heuristic backstop, not a guarantee. New
hashing algorithms and authentication methods drop in without framework changes (sub-interface +
record + registration call). Shared-secret failures intentionally cost up to 2× the default
hasher's work to close the rotation-window timing gap; public-client timing remains
distinguishable from confidential-client timing as an accepted residual. Multiple-hasher
deployments require an explicit `isDefault: true` — ambiguity is a startup failure, not a silent
choice. Migrating from a `string?`-secret or verifier-on-registration prototype requires adopting
the `Credentials`/hasher split; acceptable pre-1.0, since no consumer code exists against the old
shape yet.
