# ADR 0007 — Client Registration Model

**Status:** Accepted  
**Date:** 2026-06-07

---

## Context

ZeeKayDa.Auth must answer for every incoming request: *Is this client known? What is it allowed to do?* This ADR fixes the data model and lookup abstraction for registered clients.

Key forces:

- **Static registration only (v1).** Dynamic registration (RFC 7591) is deferred; all clients are registered at startup.
- **Public vs confidential clients** (RFC 6749 §2.1). The type system must represent this clearly and enforce it consistently.
- **Redirect URI security.** RFC 9700 §2.1 mandates exact-string comparison; URI manipulation is one of the most common OAuth vulnerabilities.
- **Scope intersection.** ADR 0005 §7 established that `IConsentInteraction.GrantAsync` intersects granted scopes with `AllowedScopes`. The client registration model is the authoritative source.
- **Layering.** Core (`ZeeKayDa.Auth`) owns registration data and stored-secret hashing. Request-aware token endpoint authentication belongs to `ZeeKayDa.Auth.AspNetCore`.
- **OAuth 2.1 alignment.** PKCE is mandatory for all clients; implicit and ROPC flows are removed.

---

## Decision

### 1. `IClientRegistration` interface

```csharp
namespace ZeeKayDa.Auth.Clients;

public interface IClientRegistration
{
    string ClientId { get; }

    /// Credentials for this client. Empty list = public client.
    /// Use Credentials.OfType<IClientSecret>() for secret-based auth.
    IReadOnlyList<IClientCredential> Credentials { get; }

    /// True iff Credentials.Count == 0 AND AllowedTokenEndpointAuthMethods == { "none" }.
    /// Declared (non-DIM) — enforced at registration time (§6).
    bool IsPublic { get; }

    IReadOnlySet<string> RedirectUris { get; }
    IReadOnlySet<string> PostLogoutRedirectUris { get; }
    IReadOnlySet<string> AllowedScopes { get; }
    IReadOnlySet<GrantType> AllowedGrantTypes { get; }
    IReadOnlySet<ResponseType> AllowedResponseTypes { get; }
    IReadOnlySet<ResponseMode> AllowedResponseModes { get; }
    IReadOnlySet<string> AllowedTokenEndpointAuthMethods { get; }
    IReadOnlySet<PromptValue> AllowedPromptValues { get; }
    bool EnableZkdErrorCodes { get; }

    // DIM — null means "inherit IdTokenOptions.SigningAlgValuesSupported".
    IReadOnlySet<SigningAlgorithm>? AllowedSigningAlgorithms => null;
}
```

**Why interface:** custom `IClientRepository` implementations can make their own entity types implement `IClientRegistration` directly — no framework-type mapping step on the hot path.

**`IsPublic` is declared (non-DIM):** a silent DIM default would convert a configuration omission into a security-relevant runtime behaviour change (same reasoning as `PostLogoutRedirectUris`). Three-way consistency rule: `IsPublic ⇔ Credentials.Count == 0 ⇔ AllowedTokenEndpointAuthMethods == { "none" }`. Enforced at startup (§6).

**No `RequirePkce` flag.** OAuth 2.1 §7.6 mandates PKCE unconditionally; there is no per-client opt-out.

**`AllowedPromptValues` default: `new HashSet<PromptValue>()`** (empty = all OIDC Core §3.1.2.1 values permitted). An explicit full-set default is a forward-compat trap when new `PromptValue` members are added.

**Deferred to v2** (added as DIM-defaulted properties to preserve binary compatibility): display metadata (`ClientName`, `LogoUri`, etc.), PAR (`RequirePushedAuthorizationRequests`), token lifetime overrides.

**String set comparison invariant.** All `IReadOnlySet<string>` members on `IClientRegistration` (`RedirectUris`, `PostLogoutRedirectUris`, `AllowedScopes`, `AllowedTokenEndpointAuthMethods`) MUST be enumerated with explicit `StringComparer.Ordinal` semantics by every consumer in this ADR (§4, §5, §6, §8). The set's own comparer is NOT trusted — a custom `IClientRepository` may return an entity-implemented `IClientRegistration` whose set was constructed with `OrdinalIgnoreCase` or another non-ordinal comparer. Consumers do not opt in; ordinal comparison is the contract.

### 1a. Enum vs string for per-client vocabularies

- **Enum** when a new value requires framework-side implementation: `GrantType`, `ResponseType`, `ResponseMode`, `PromptValue`.
- **`IReadOnlySet<string>`** when a public extension point carries a new value end-to-end without core changes: `AllowedTokenEndpointAuthMethods` (any `IClientAuthenticator` can introduce a new method such as `tls_client_auth`). Membership checks MUST use `StringComparer.Ordinal`.
- `TokenEndpointAuthMethods` constants class (`ClientSecretBasic`, `ClientSecretPost`, `None`) eliminates magic strings for ZeeKayDa-handled values.

**Amendment to ADR 0002 and ADR 0003 — `TokenEndpointAuthMethod` reclassified as an open extension point.** The earlier draft kept the existing `TokenEndpointAuthMethod` *enum* (used by discovery via `TokenEndpointOptions.AuthMethodsSupported`) separate from `AllowedTokenEndpointAuthMethods`. That is inconsistent: a host registering a custom `IClientAuthenticator` for, say, `tls_client_auth` can configure clients with `AllowedTokenEndpointAuthMethods = { "tls_client_auth" }`, but the discovery document (driven by the enum) cannot advertise it — a misleading `token_endpoint_auth_methods_supported` value (OIDC Discovery §3 requires the field to list methods the server actually supports). The unified design is:

- `TokenEndpointOptions.AuthMethodsSupported` becomes `ICollection<string>` (ordinal), defaulting to `[TokenEndpointAuthMethods.ClientSecretBasic]`.
- The discovery document's `token_endpoint_auth_methods_supported` is exactly `TokenEndpointOptions.AuthMethodsSupported` after startup validation. This is the operator's global server allowlist. Registered authenticators are capability providers, not automatic advertisement.
- Startup validation ensures every configured server method has at least one registered `IClientAuthenticator`, and every in-memory client's `AllowedTokenEndpointAuthMethods` is a subset of `TokenEndpointOptions.AuthMethodsSupported`.
- Custom methods are enabled by doing both: register an `IClientAuthenticator` whose `AuthenticationMethods` contains the method string, and add that same string to `TokenEndpointOptions.AuthMethodsSupported`.
- The `TokenEndpointAuthMethod` enum is removed. Strings carry the vocabulary end-to-end across registration, dispatch, and discovery; the `TokenEndpointAuthMethods` constants class covers framework-handled values, and extension authors add their own string constants alongside their `IClientAuthenticator`.

Implementation of this amendment (changing `TokenEndpointOptions`, `DiscoveryDocumentProvider`, `OpenIdConfigurationDocument`, validators, and tests) is tracked in a follow-up implementation issue and is **not** part of this ADR's PR. ADR 0002 and ADR 0003 carry an amendment note pointing back to this section.

### 2. `ClientRegistration` sealed record

```csharp
public sealed record ClientRegistration : IClientRegistration
{
    public required string ClientId { get; init; }
    public required IReadOnlyList<IClientCredential> Credentials { get; init; }
    public required bool IsPublic { get; init; }
    public required IReadOnlySet<string> RedirectUris { get; init; }
    public required IReadOnlySet<string> PostLogoutRedirectUris { get; init; }

    public IReadOnlySet<string> AllowedScopes { get; init; }
        = new HashSet<string>(StringComparer.Ordinal);
    public IReadOnlySet<GrantType> AllowedGrantTypes { get; init; }
        = new HashSet<GrantType> { GrantType.AuthorizationCode };
    public IReadOnlySet<ResponseType> AllowedResponseTypes { get; init; }
        = new HashSet<ResponseType> { ResponseType.Code };
    public IReadOnlySet<ResponseMode> AllowedResponseModes { get; init; }
        = new HashSet<ResponseMode> { ResponseMode.Query, ResponseMode.FormPost };
    public IReadOnlySet<string> AllowedTokenEndpointAuthMethods { get; init; }
        = new HashSet<string>(StringComparer.Ordinal) { TokenEndpointAuthMethods.ClientSecretBasic };
    public IReadOnlySet<PromptValue> AllowedPromptValues { get; init; }
        = new HashSet<PromptValue>();   // empty = all prompt values permitted
    public bool EnableZkdErrorCodes { get; init; }
    public IReadOnlySet<SigningAlgorithm>? AllowedSigningAlgorithms { get; init; }

    // Factory methods — signatures only; bodies are implementation.
    public static ClientRegistration CreateConfidential(
        IClientSecretHasher hasher, string clientId, string clientSecret,
        IEnumerable<string> redirectUris, IEnumerable<string> postLogoutRedirectUris,
        IEnumerable<string> allowedScopes, ...);

    public static ClientRegistration CreatePublic(
        string clientId, IEnumerable<string> redirectUris,
        IEnumerable<string> postLogoutRedirectUris, IEnumerable<string> allowedScopes, ...);
}
```

Validation lives in `IClientRegistrationValidator` (§6.1), not the record constructor — keeps the record a pure value object so tests can construct invalid instances to exercise the validator. `InMemoryClientRepository` invokes the validator on every registration during construction; custom repositories invoke it at write time (or first read for read-mostly stores).

### 3. Credential model

#### 3.1 Credential interfaces

```csharp
/// Empty marker for all credential types stored on a client.
public interface IClientCredential { }

/// Marker for shared-secret credentials. Pure data — no behaviour.
public interface IClientSecret : IClientCredential { }

/// PBKDF2-hashed secret.
public interface IPbkdf2ClientSecret : IClientSecret
{
    int Iterations { get; }
    byte[] Salt { get; }
    byte[] Hash { get; }
}

public sealed record Pbkdf2ClientSecret(int Iterations, byte[] Salt, byte[] Hash)
    : IPbkdf2ClientSecret;
```

The C# type identity is the algorithm — no `string Algorithm` discriminator. A consumer adding bcrypt defines `IBCryptClientSecret : IClientSecret` with a paired `ClientSecretHasher<IBCryptClientSecret>`.

**Credential rotation:** at most two active `IClientSecret` entries are valid simultaneously during a rollover window. Authenticators MUST try ALL `client.Credentials.OfType<TCredential>()` before returning `NotValid`; a failed first credential MUST NOT stop the search. Registration validation rejects more than two active shared-secret credentials for a client.

**Deferred to v2:** `IJwksCredential : IClientCredential` (for `private_key_jwt`; carries `JwksUri` or inline JWKS). This will be the first non-secret `IClientCredential` subtype.

**Buffer ownership.** `Pbkdf2ClientSecret.Salt` and `Pbkdf2ClientSecret.Hash` expose their underlying `byte[]` arrays directly — intentional for ORM-mapper friendliness (§10, D2). The framework treats both as read-only after construction and does NOT defensively copy. Consumers building registrations from external sources own the buffer lifetime. Salts and PBKDF2 output hashes are not secret values, so this is a documented contract rather than a security concern.

#### 3.2 `IClientSecretHasher`

```csharp
public interface IClientSecretHasher
{
    bool CanHandle(IClientSecret secret);
    bool Verify(IClientSecret stored, ReadOnlySpan<char> presented);
    IClientSecret Create(string plaintext);
}

public abstract class ClientSecretHasher<TSecret> : IClientSecretHasher
    where TSecret : IClientSecret
{
    public bool CanHandle(IClientSecret secret) => secret is TSecret;
    public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented);
    public IClientSecret Create(string plaintext);     // rejects null/empty/whitespace
    protected abstract bool VerifyCore(TSecret stored, ReadOnlySpan<char> presented);
    protected abstract TSecret CreateCore(string plaintext);
}
```

Implementations MUST: use `CryptographicOperations.FixedTimeEquals`; never throw from `Verify` (return `false` on internal error); never log the presented secret; be singleton-safe.

#### 3.3 `Pbkdf2ClientSecretHasher` — framework default

| Parameter | Value |
|---|---|
| Algorithm | PBKDF2-HMAC-SHA256 |
| Default iterations | 600,000 (current OWASP guidance) |
| Minimum iterations | 600,000 (constructor-enforced; matches current OWASP PBKDF2-HMAC-SHA256 guidance — equal to the default so operators can only configure stronger, never weaker) |
| Salt | 16 bytes (`RandomNumberGenerator.GetBytes`) |
| Hash | 32 bytes |

`VerifyCore` rejects an empty `presented` span explicitly (defence-in-depth against a stored hash of "").

#### 3.4 `CompositeClientSecretHasher` — internal coordinator

```csharp
internal sealed class CompositeClientSecretHasher
{
    // Pre-computes _dummySecret via the resolved default hasher at startup.
    // Intentional one-time cost (~600 ms for PBKDF2 at 600k iterations).
    public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented);
    public IClientSecret Create(string plaintext);
    internal bool VerifyUnknownClientForTimingOnly(ReadOnlySpan<char> presented);
    internal void PadFailureToCredentialBudget(int attemptedCredentials);
}
```

**Timing oracle.** `PadTiming()` (runs `_default.Verify(_dummySecret, _dummyPresented)`) fires only when the matched hasher is NOT the default:

```csharp
if (!result && !ReferenceEquals(h, _default))
    PadTiming();
```

Rationale: in standard deployments (single PBKDF2 hasher = the default), a single failed stored-secret verification and one dummy verification have equivalent work. `PadTiming()` only adds work when a faster custom hasher matched — preventing that hasher from reopening a timing oracle.

**Fixed failure budget for rotation:** token endpoint shared-secret failure paths pad to `MaxActiveSharedSecretsPerClient = 2` verification-equivalent operations:

- Unknown client: run `VerifyUnknownClientForTimingOnly` twice.
- Known client with one active secret and wrong credential: run one real verification, then one dummy default verification.
- Known client with two active secrets and wrong credential: run two real verifications.
- Fast custom hasher failures still call `PadTiming()` per failed custom verification before the remaining credential-budget padding is applied.

This intentionally makes ordinary failure paths cost up to 2× PBKDF2 so a client in a rotation window is not distinguishable from an unknown client by timing. Rate limiting remains the primary enumeration defence; timing uniformity is necessary but not sufficient.

**Accepted residual: public-client distinguishability.** The `none` authentication path is intrinsically faster than any shared-secret verification and cannot be padded to the same budget without an unconditional dummy PBKDF2 on every token endpoint hit (rejected: imposes a flat 600 ms cost on the most common production case). An attacker can therefore distinguish a public-client `client_id` from a confidential `client_id` by timing the response. This is accepted; the protocol-level distinction is unavoidable and rate limiting is the only effective defence (RFC 9700 §2.1).

`CompositeClientSecretHasher` is registered as the **concrete type**, not as `IClientSecretHasher`, to prevent self-injection through `IEnumerable<IClientSecretHasher>` (which would cause infinite recursion on first `Verify`).

#### 3.5 Hasher DI registration

```csharp
public static ZeeKayDaAuthBuilder AddSecretsHasher<THasher>(
    this ZeeKayDaAuthBuilder builder, bool isDefault = false)
    where THasher : class, IClientSecretHasher;
```

`ClientSecretHasherOptionsValidator` enforces at startup:

| Registered hashers | Explicit defaults | Outcome |
|---|---|---|
| 1 | 0 or 1 | That hasher is the default |
| 2+ | 1 | Flagged type is the default |
| 2+ | 0 | Startup failure |
| 2+ | 2+ | Startup failure |
| 0 | any | Startup failure |

### 4. `IClientAuthenticator` — self-describing dispatch

```csharp
namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

public interface IClientAuthenticator
{
    /// Method strings this authenticator can produce (used for startup coverage
    /// validation against TokenEndpoint.AuthMethodsSupported). Ordinal comparison.
    IReadOnlySet<string> AuthenticationMethods { get; }

    /// TryParse-style detection. Returns true if this request carries authentication
    /// material this authenticator handles, and writes the matched method name to
    /// `method` — one of the values in `AuthenticationMethods`. Returns false and
    /// `method = null` otherwise. MUST be a cheap shape check (no crypto, no DB).
    /// The client has not been resolved at this point; only request-shape data is available.
    bool CanHandle(TokenRequestContext context, out string? method);

    /// Invoked only after the composite has confirmed exactly this authenticator
    /// detected and the matched method is on both allowlists. The client in `context`
    /// is guaranteed non-null. Authenticators that handle multiple methods (e.g.
    /// ClientSecretAuthenticator handles client_secret_basic AND client_secret_post)
    /// must re-derive the branch from the same cheap shape check used in CanHandle.
    ValueTask<ClientAuthenticationResult> AuthenticateAsync(
        ClientAuthenticationContext context,
        CancellationToken cancellationToken);
}

/// <summary>
/// Holds the request-shape information available during <see cref="IClientAuthenticator.CanHandle"/>.
/// The client has not yet been resolved from the repository at this point.
/// </summary>
/// <remarks>
/// <c>Form</c> and <c>Headers</c> are required init properties rather than being derived from
/// <c>HttpContext</c> on demand. <c>HttpRequest.Form</c> is synchronous and throws on non-form
/// content types — both attacker-controllable. <c>Headers</c> is captured at construction time
/// so all authenticators see a consistent snapshot. The token endpoint pre-reads the form body
/// asynchronously before constructing this context.
/// </remarks>
public class TokenRequestContext
{
    public required HttpContext HttpContext { get; init; }
    public required string ClientId { get; init; }
    public required IFormCollection Form { get; init; }
    public required IHeaderDictionary Headers { get; init; }
}

/// <summary>
/// Extends <see cref="TokenRequestContext"/> with the resolved client. Passed to
/// <see cref="IClientAuthenticator.AuthenticateAsync"/> after all pre-authentication checks pass.
/// </summary>
/// <remarks>
/// <c>Client</c> is non-nullable by construction: the composite only creates this context
/// once the client has been successfully resolved from <see cref="IClientRepository"/>. This
/// eliminates a null-dereference class from custom authenticator implementations and removes
/// the need for a nullable-client guard in every <c>AuthenticateAsync</c> body.
/// </remarks>
public sealed class ClientAuthenticationContext : TokenRequestContext
{
    public required IClientRegistration Client { get; init; }
}

public sealed record ClientAuthenticationResult
{
    public required bool Authenticated { get; init; }

    public static ClientAuthenticationResult Valid();
    public static ClientAuthenticationResult NotValid();
}
```

**`TokenRequestContext` / `ClientAuthenticationContext` split.** The ADR was drafted with a single `ClientAuthenticationContext` whose `Client` property was `IClientRegistration?` (nullable) — the client might or might not be resolved depending on the call site. The implementation splits this into two types: `TokenRequestContext` (no client, used in `CanHandle`) and `ClientAuthenticationContext : TokenRequestContext` (non-null `Client`, used in `AuthenticateAsync`). This is strictly better than the nullable shape: `CanHandle` correctly receives only the data available at its call point (the client has not yet been fetched), and `AuthenticateAsync` receives a type-level guarantee that `Client` is non-null. The nullable variant would force every `AuthenticateAsync` implementation to either null-guard or suppress warnings, and leaves open the question of what "null client passed to AuthenticateAsync" means. The split closes that question by construction.

**`method` parameter dropped from `AuthenticateAsync`.** The earlier draft passed the matched method string back into `AuthenticateAsync` so multi-method authenticators (e.g. `ClientSecretAuthenticator` handling both `client_secret_basic` and `client_secret_post`) could branch without re-deriving. The implementation dropped this parameter. Rationale: the method-detection logic in `CanHandle` is a cheap shape check (header presence, form-field presence) — repeating it in `AuthenticateAsync` costs nothing measurable and is safer than threading a string through the composite where it could be misrouted or stale. Keeping `AuthenticateAsync` free of the `method` string also simplifies the composite (no string storage between `CanHandle` and `AuthenticateAsync`) and eliminates a class of bugs where the passed `method` disagrees with what the request actually contains. Implementers that need the branch must re-derive from the same cheap check.

**`Form` and `Headers` as required init properties.** `HttpRequest.Form` is a synchronous property that throws `InvalidOperationException` on non-form content types and blocks under `AllowSynchronousIO = false` (the ASP.NET Core default since 3.0). Both conditions are attacker-controllable. `HttpRequest.Headers` is not volatile but reading it inside each authenticator creates no consistent-snapshot guarantee across multiple authenticators in the same pipeline. The token endpoint pre-reads the form body asynchronously once, then supplies `Form` and `Headers` as init properties on `TokenRequestContext`, so every authenticator sees the same immutable snapshot and the synchronous-access hazard is eliminated at the boundary.

**Dispatch rules (`CompositeClientAuthenticator`).** The composite has **zero method-specific knowledge for credential-bearing methods**; it never inspects the request to identify `client_secret_basic`, `client_secret_post`, `tls_client_auth`, etc. Detection is delegated entirely to authenticators. The one reserved special case is `none`: absence of client authentication material is a composite fallback after every credential-bearing authenticator declines.

1. Construct a `TokenRequestContext` (pre-read form, captured headers). Call `CanHandle(context, out method)` on every registered `IClientAuthenticator`. No authenticator may declare or return `TokenEndpointAuthMethods.None` (`"none"`); `none` is reserved for the composite fallback.
2. Collect every `(authenticator, method)` pair where `CanHandle` returned `true`.
3. `count > 1` → multiple client authentication mechanisms presented → `invalid_client` (RFC 6749 §2.3).
4. `count == 0` → fall back to `method = "none"`. The fallback succeeds only if the server allows `none`, the client exists, `client.IsPublic == true`, `client.Credentials.Count == 0`, and `client.AllowedTokenEndpointAuthMethods` is exactly `{ "none" }`, all using `StringComparer.Ordinal`. Failure at any layer returns `invalid_client`. No authenticator is invoked for `none`; it represents the absence of authentication evidence, not a pluggable authentication mechanism.
5. `count == 1` → the returned `method` MUST be in this authenticator's own `AuthenticationMethods` (defends against a buggy `CanHandle` returning an undeclared method, which would otherwise bypass the startup coverage check). The matched `method` MUST be present in `TokenEndpoint.AuthMethodsSupported` (global server allowlist). The client MUST exist before any per-client allowlist check; an unknown client returns `invalid_client` with the §3.4 / §7 timing padding applied where applicable. The matched `method` MUST then be present in `client.AllowedTokenEndpointAuthMethods`, using `StringComparer.Ordinal`. Failure at any layer returns `invalid_client` without invoking `AuthenticateAsync`. The per-client method list is not a secret; failing fast here is acceptable and avoids unnecessary crypto. On success, the composite promotes the `TokenRequestContext` to a `ClientAuthenticationContext` by attaching the resolved, non-null `Client`.
6. Call `authenticator.AuthenticateAsync(context, ct)`. `Authenticated == true` → request is authenticated. `Authenticated == false` → `invalid_client` with the §3.4 / §7 timing padding applied.

**How to extend:** ship an `IClientAuthenticator` whose `CanHandle` returns `true` (with the appropriate method string) when the request carries the new mechanism's material — for example, a `TlsClientAuthAuthenticator` returning `true` with `method = "tls_client_auth"` when `HttpContext.Connection.ClientCertificate is not null`. Register it, and add `"tls_client_auth"` to `TokenEndpoint.AuthMethodsSupported`. **No composite or framework change is required.** Custom authenticators MUST NOT attempt to handle `none`; it is reserved to the composite fallback so custom positive-evidence mechanisms cannot collide with public-client detection.

**Rotation:** when an authenticator owns a request, it MUST try ALL `client.Credentials.OfType<TCredential>()` before returning `NotValid`.

**Null guard:** `ClientSecretAuthenticator` MUST check `credentials.FirstOrDefault() is null` and return `NotValid` (not throw) when the client has no matching credentials.

**v1 built-in authenticators:**

- `ClientSecretAuthenticator` — `CanHandle` returns `true` with `method = "client_secret_basic"` when an `Authorization: Basic` header is present, or `"client_secret_post"` when a `client_secret` form field is present (and rejects requests that present both, before the composite's multi-mechanism check, as belt-and-braces); delegates stored-secret verification to `CompositeClientSecretHasher`. (`client_secret_post` supported for compatibility; should be enabled only when needed as request bodies are more likely to appear in logs.)

**Startup validation:** every `TokenEndpoint.AuthMethodsSupported` value except `TokenEndpointAuthMethods.None` MUST be present in exactly one registered `IClientAuthenticator.AuthenticationMethods`; `TokenEndpointAuthMethods.None` MUST NOT appear in any registered authenticator's `AuthenticationMethods` (it is reserved to the composite fallback); and every in-memory client's `AllowedTokenEndpointAuthMethods` value MUST be a subset of `TokenEndpoint.AuthMethodsSupported`. Any failure produces `ValidateOptionsResult.Fail(...)` at startup. Custom repositories own equivalent validation.

**Layering:** because `IClientAuthenticator` lives in `ZeeKayDa.Auth.AspNetCore` (§9) but `TokenEndpointOptions` lives in `ZeeKayDa.Auth` (Core), the coverage validator necessarily lives in AspNetCore and cannot be a Core `IValidateOptions<TokenEndpointOptions>` implementation. Implementation issues shipping this validator MUST place it in the AspNetCore package.

### 5. Redirect URI validation

Rules enforced at registration time (by `IClientRegistrationValidator`, §6.1) and request time (belt-and-suspenders for custom repositories):

1. **Exact ordinal string match** — enumerate registered strings with `StringComparer.Ordinal`; do not trust the `IReadOnlySet` instance's own comparer.
2. **RFC 8252 §7.3 loopback-port exception** — port component ignored for loopback hosts at match time only.
3. **No fragment** — `Uri.Fragment` non-empty → rejected (RFC 6749 §3.1.2).
4. **No userinfo** — `Uri.UserInfo` non-empty → rejected.
5. **No `.`/`..` path segments** — ambiguous canonicalisation.
6. **Scheme allowlist (pure allowlist — no blocklist)** — `https` (any host); `http` (loopback only); any private-use scheme that contains a `.` (RFC 8252 §7.1 reverse-domain convention). All other schemes rejected. The implementation is a pure allowlist and deliberately omits any `ForbiddenSchemes` blocklist: schemes such as `javascript`, `data`, `file`, `vbscript`, `about`, `blob`, `ws`, `wss`, `ftp`, `mailto`, and `tel` contain no dot and are therefore already rejected by the allowlist. The dot requirement makes a separate blocklist vacuous, so none is maintained.
7. **`localhost`** emits `LogWarning` recommending the IP literal (RFC 8252 §8.3). Loopback test uses whole-string match, never substring (`localhost.attacker.com` correctly fails).
8. At most **32 redirect URIs** per client.
9. All rules apply equally to `PostLogoutRedirectUris` (may be empty).

Loopback test: `string.Equals(uri.Host, "localhost", OrdinalIgnoreCase) || (IPAddress.TryParse(uri.Host, out var ip) && IPAddress.IsLoopback(ip))`. Use `Uri` structured properties throughout — no raw string operations on URI values.

### 6. `IClientRepository` and `InMemoryClientRepository`

```csharp
public interface IClientRepository
{
    ValueTask<IClientRegistration?> FindByClientIdAsync(
        string clientId, CancellationToken cancellationToken = default);
}
```

Contract: return `null` (never throw) for unknown or malformed `client_id` — throwing changes timing and undermines enumeration defence. Lookup MUST be parametrised at the storage layer (no string concatenation into queries).

`InMemoryClientRepository` validates all registrations at construction time by delegating to `IClientRegistrationValidator` (§6.1); failures throw `ZeeKayDaConfigurationException` before the host starts accepting requests.

**No default `IClientRepository` is registered** by `AddZeeKayDaAuth`; its absence is caught by `ClientRepositoryPresenceValidator : IValidateOptions<AuthorizationServerOptions>` with `ValidateOnStart()`. A default `IClientRegistrationValidator` (§6.1) **is** registered unconditionally so every repository implementation can resolve and call it.

**Consistency rule at registration time:**

| `IsPublic` | `Credentials.Count` | `AllowedTokenEndpointAuthMethods` |
|---|---|---|
| `true` | `0` | exactly `{ "none" }` |
| `false` | `> 0` | non-empty AND MUST NOT contain `"none"` |

A confidential client with an empty `AllowedTokenEndpointAuthMethods` can never authenticate at the token endpoint, so it is rejected at registration as misconfiguration.

**Additional registration-time checks:**

- `ClientId` matches `[A-Za-z0-9_\-.]+`, max 200 chars. Duplicate detection and in-memory dictionary lookup use `StringComparer.Ordinal`.
- Confidential clients: `CompositeClientSecretHasher.Verify(credential, ReadOnlySpan<char>.Empty)` MUST return `false` for every `IClientSecret` in `Credentials` (defence-in-depth against a broken hasher that accepts empty input).
- Confidential clients may have at most two active `IClientSecret` credentials (fixed failure-budget invariant for rotation timing).
- `AllowedSigningAlgorithms` non-null ⇒ non-empty (shape check); subset check against `IdTokenOptions.SigningAlgValuesSupported` runs via `IValidateOptions<…>` at host startup (best-effort for in-memory clients; custom repositories must enforce their own subset validation).
- `AllowedScopes` contains no empty/whitespace entries.
- `AllowedTokenEndpointAuthMethods` values are non-null, non-empty, have no leading/trailing whitespace, contain no control characters, are ordinal-distinct, and are a subset of `TokenEndpointOptions.AuthMethodsSupported`.
- `Enum.IsDefined` for all enum-typed sets (guards against `(GrantType)999`-style casts).
- No duplicate `client_id` within the repository (ordinal).
- `TokenEndpointOptions.AuthMethodsSupported` SHOULD NOT contain `"none"` unless at least one registered client is public (`IsPublic == true`). Advertised but unused, `none` is a misconfiguration smell rather than an exploit. The framework logs a startup warning rather than failing.

**ID-token signing at issuance:** effective set = `client.AllowedSigningAlgorithms ?? IdTokenOptions.SigningAlgValuesSupported`. Issuance MUST fail if no configured signing credential satisfies the effective set. Startup validation is best-effort early warning; issuance time is the security boundary.

**DI wiring:**

```csharp
builder.AddInMemoryClients(clients => {
    clients.AddConfidential(clientId: "...", clientSecret: "...", redirectUris: ..., allowedScopes: ...);
    clients.AddPublic(clientId: "...", redirectUris: ..., allowedScopes: ...);
    clients.Add(preHashedRegistration);
});
```

`AddInMemoryClients(Action<IInMemoryClientRegistrationBuilder>)` accepts a callback that populates an `IInMemoryClientRegistrationBuilder`. Each call is additive; multiple `AddInMemoryClients(...)` calls accumulate — no silent Replace. The callback executes during service registration and records pending registrations. The accumulated list is snapshot-frozen when the `IClientRepository` singleton is constructed.

`IInMemoryClientRegistrationBuilder` exposes:

- `AddPublic(...)` — creates a public `ClientRegistration`.
- `AddConfidential(..., string clientSecret, ...)` — records the plaintext secret temporarily; the repository hashes it with the configured default `CompositeClientSecretHasher.Create(...)` during repository construction, then stores only `IClientSecret` credentials.
- `Add(IClientRegistration registration)` — accepts a pre-built/pre-hashed registration for advanced scenarios and tests.

`AddSecretsHasher<T>(bool isDefault = false)` is the second builder extension.

**Why a callback, not `IEnumerable<IClientRegistration>`:** scope definitions are simple value objects; client registrations are complex — they carry credentials, URI sets, grant-type sets, and signing algorithm constraints. A callback is more discoverable, naturally additive, and gives the in-memory builder access to DI-resolved hashing at repository construction without leaking service resolution into user configuration. `AddInMemoryScopes` keeps its `IEnumerable<ScopeDefinition>` shape — different types have different needs, consistency is not a goal here.

### 6.1 `IClientRegistrationValidator` — shared rule enforcement

To avoid duplicating the §5 redirect URI rules and the §6 consistency/shape checks across every `IClientRepository` implementation, the framework exposes the rules as a public service:

```csharp
namespace ZeeKayDa.Auth.Clients;

public interface IClientRegistrationValidator
{
    /// Throws ZeeKayDaConfigurationException whose AggregatedFailures
    /// enumerates every rule violation. MUST aggregate, not fail-fast,
    /// so operators see every problem in one pass.
    void Validate(IClientRegistration client);
}
```

The framework registers a default `ClientRegistrationValidator` implementation that enforces every rule listed in §5 and §6 — the redirect URI matrix, the `IsPublic` consistency table, `ClientId` charset/length, the empty-secret probe on every `IClientSecret`, the two-active-shared-secret cap, `AllowedSigningAlgorithms` shape and subset against `IdTokenOptions.SigningAlgValuesSupported`, `AllowedScopes` and `AllowedTokenEndpointAuthMethods` hygiene, the subset check against `TokenEndpointOptions.AuthMethodsSupported`, and `Enum.IsDefined` on every enum-typed set.

The validator depends on `IOptions<TokenEndpointOptions>`, `IOptions<IdTokenOptions>`, and the framework-internal `CompositeClientSecretHasher` (concrete type) for the empty-secret probe. It is registered as a singleton.

**Who calls it:**

- `InMemoryClientRepository` invokes it on every pending registration during its construction; any failure throws before the host starts accepting requests.
- Custom `IClientRepository` implementations MUST resolve `IClientRegistrationValidator` from DI and call it before persisting a new or updated client. For read-mostly stores populated outside of the host (e.g. migrated from another IdP, or a read-replica), implementations MUST call it at some deterministic point before serving a registration — typically when loading into an internal cache — and MUST NOT return a registration that fails validation.
- The future dynamic client registration handler (RFC 7591, §10) MUST call it before persisting any `/register` request.

**Why a service, not an `Initialize` method on the repository:** the "validate everything once at startup" pattern is a property of the in-memory storage lifecycle, not a feature of the abstraction. Database-backed and dynamic-registration repositories validate at write time — startup full-table validation is either infeasible (millions of rows) or misleading (clients added later via admin/DCR APIs would skip it). Extracting the rules into `IClientRegistrationValidator` lets every repository call the same rule set at the moment that fits its lifecycle, without forcing a ceremonial `InitializeAsync` that would be a no-op for most real implementations.

**Defence in depth:** the §4 dispatch rules and §7 enumeration mitigations remain unconditional at request time. A validator gap in a custom repository surfaces as runtime `invalid_client` / `invalid_request` rejections — incorrect operator-visible behaviour, never an exploit window.

### 7. Client enumeration mitigation

- **Token endpoint:** `invalid_client` for both unknown `client_id` and wrong credential. `error_description` MUST NOT include the `client_id`.
- **`zkd_error` non-disclosure constraint (binding):** when `EnableZkdErrorCodes` is `true`, the `zkd_error` value for `invalid_client` MUST NOT distinguish "unknown client_id" from "wrong credential". Any token-endpoint ADR or implementation that adds `zkd_error` codes MUST respect this constraint.
- **Timing:** shared-secret failure paths pad to the fixed two-credential budget in §3.4. `CompositeClientSecretHasher.VerifyUnknownClientForTimingOnly(presented)` pads the unknown-client path; `PadTiming()` pads non-default-hasher failures before remaining credential-budget padding is applied.
- **Authorization endpoint:** unknown `client_id` fails before any redirect; the generic error page MUST NOT echo the `client_id` unencoded.
- **Logs and metrics:** externally observable logs, metrics, diagnostics, and `zkd_error` values MUST NOT distinguish unknown client from wrong credential. Logs MUST never include presented client secrets, raw `Authorization` headers, raw token endpoint request bodies containing `client_secret`, or `code_verifier` values (RFC 7636 §7.5 — single-use, but logging within the verifier's validity window enables interception-attack completion).
- **Rate limiting** is the operator's responsibility; timing uniformity is necessary but not sufficient to defeat a sustained enumeration attempt.

**Binding forward constraints on the token endpoint (for the future token-endpoint ADR):**

1. Token endpoint client authentication MUST delegate to `CompositeClientAuthenticator`, which dispatches to a registered `IClientAuthenticator`. For shared-secret methods, `ClientSecretAuthenticator` MUST delegate stored-secret verification to `CompositeClientSecretHasher.Verify(...)`. **The framework MUST NOT compare secret strings itself** — all comparisons go through a hasher so fixed-time equality is centrally guaranteed.
2. `IsPublic == true` (equivalently `Credentials.Count == 0`) means "public client" — any presented client authentication material MUST cause rejection with `invalid_client`. Public clients are authenticated only by the composite's `none` fallback after all credential-bearing authenticators decline.
3. The unknown-client path MUST call `CompositeClientSecretHasher.VerifyUnknownClientForTimingOnly(presented)` enough times to match the fixed two-credential failure budget.
4. The authorize endpoint MUST reject any incoming request whose `redirect_uri` parameter contains a URI fragment (RFC 6749 §3.1.2) before performing the exact-ordinal match against `RedirectUris`. The registration-time "no fragment" rule (§5) makes this defence-in-depth — even a future loosening of the match rule cannot accidentally re-enable a fragment-bearing redirect.

### 8. Scope intersection

```
effective_scopes = (requested_scopes ∩ client.AllowedScopes) ∩ user_granted_scopes
```

- Scopes not in `AllowedScopes` are silently dropped; empty effective set → `invalid_scope` (RFC 6749 §4.1.2.1). Dropped scope names MUST NOT appear in error responses.
- `IConsentInteraction.GrantAsync` re-intersects with `AllowedScopes` as a last line of defence (ADR 0005 §7) — a host bug cannot grant scopes the client was not registered for.
- Comparison: `StringComparer.Ordinal`.

### 9. Package ownership

| Concern | Package |
|---|---|
| `IClientRegistration`, `ClientRegistration`, `IClientCredential`, `IClientSecret`, `IPbkdf2ClientSecret`, `Pbkdf2ClientSecret` | `ZeeKayDa.Auth` |
| `IClientSecretHasher`, `ClientSecretHasher<T>`, `Pbkdf2ClientSecretHasher`, `CompositeClientSecretHasher` (internal) | `ZeeKayDa.Auth` |
| `IClientRepository`, `InMemoryClientRepository`, `IClientRegistrationValidator`, `ClientRegistrationValidator` | `ZeeKayDa.Auth` |
| `TokenEndpointAuthMethods`, `PromptValue`, `GrantType`, `ResponseType`, `ResponseMode` | `ZeeKayDa.Auth` |
| `IClientAuthenticator`, `TokenRequestContext`, `ClientAuthenticationContext`, `ClientAuthenticationResult` | `ZeeKayDa.Auth.AspNetCore` |
| `ClientSecretAuthenticator`, `CompositeClientAuthenticator` (internal) | `ZeeKayDa.Auth.AspNetCore` |
| `AddInMemoryClients` (`IInMemoryClientRegistrationBuilder`), `AddSecretsHasher<T>` | `ZeeKayDa.Auth.AspNetCore` |

### 10. Forward compatibility with RFC 7591 dynamic client registration

Dynamic registration is out of scope for v1, but the v1 abstractions are deliberately shaped so a future `ZeeKayDa.Auth.DynamicClients` package can layer on without breaking changes:

- A future `DynamicClientRepository` will be a **decorator** that wraps an internal mutable `IWritableClientRepository` (handling persistence) and exposes the RFC 7591 `/register` endpoint. The read-only `IClientRepository` surface in this ADR is the read side of that future split.
- Policy is kept separate from storage: a separate `IDynamicClientRegistrationPolicy` interface will gate which metadata fields a self-registering client may set, what scopes/grant types it may request, and any rate limiting. Keeping policy out of the repository keeps the policy decisions testable in isolation and ensures the static-registration guarantees this ADR establishes (validation, consistency rules, redirect URI rules) are not eroded by the dynamic-registration code path — the dynamic path runs the same `IClientRegistrationValidator` (§6.1) before persisting.
- No changes to `IClientRegistration`, `IClientCredential`, or the hasher contracts are anticipated; dynamic registration adds a new write surface, not a new data shape.

### 11. Documentation requirements

The following docs deliverables fall out of this ADR and must be tracked in the docs follow-up PR (one issue per item, or a single tracking issue with checkboxes):

- **D1.** Custom `IClientRepository` implementer's contract — parametrised lookup (no SQL concatenation), `null`-not-throw rule for unknown clients, the obligation to resolve `IClientRegistrationValidator` from DI and invoke it before persisting a new or updated client (or before serving a read-mostly registration; see §6.1), the rule-by-rule reference into §5/§6 for implementers that need to validate against a constrained schema, and an example skeleton.
- **D2.** Storing client credentials across ORMs — worked examples for EF Core (`IPbkdf2ClientSecret` via flat `Pbkdf2Iterations` / `Pbkdf2Salt` / `Pbkdf2Hash` columns projected through `[NotMapped]`), NHibernate (component mapping), and Dapper (query projection). Includes a guide to implementing a new hasher: define the sub-interface, define the record, subclass `ClientSecretHasher<TSecret>`, register with `AddSecretsHasher<T>()` (with `isDefault: true` if it should be the create-time default). Recommends against storing plaintext secrets at rest.
- **D3.** Every sample-code block that uses a plaintext secret literal (e.g. `clientSecret: "s3cr3t"` in a `CreateConfidential` call) must carry a prominent warning that the literal is illustrative only and unsuitable for production.
- **D4.** A note on `localhost` vs `127.0.0.1` citing RFC 8252 §8.3 and explaining why the framework emits an advisory warning on `localhost`.
- **D5.** `SECURITY.md` (or `docs/security/redirect-uri-validation.md`) capturing the scheme allowlist, loopback-port exception, userinfo prohibition, exact-ordinal matching requirement (enumerate registered strings; do not trust the `IReadOnlySet` comparer), the edge-case matrix from §5, and the threat model that motivates each rule. The matrix MUST cover: percent-encoding (`https://app/cb%20x` ≠ `https://app/cb x` — no normalisation is performed; the registered string must match the exact wire form the client will send), IPv6 loopback (`[::1]` accepted; `[::1%eth0]` zone identifier rejected), `localhost` substring traps (`localhost.attacker.com` correctly fails), and incoming-request fragment rejection at the authorize endpoint (binding constraint §7 #4).
- **D6.** An `AllowedResponseModes` doc note explaining that `fragment` is intentionally unsupported, pointing at the Rejected Alternatives entry.
- **D7.** A PKCE-mandatory FAQ entry citing RFC 9700 §2.1.1 and OAuth 2.1 §7.6, explaining why there is no per-client `RequirePkce` opt-out.
- **D8.** A client-authentication extensibility note distinguishing `IClientAuthenticator` (token endpoint request authentication) from `IClientSecretHasher` (stored shared-secret creation/verification), warning that `client_secret_post` should be enabled only for compatibility, and documenting auth-method coverage validation.
- **D9.** A signing-algorithm enforcement note for custom repositories: startup subset validation is best-effort, but issuance MUST use `client.AllowedSigningAlgorithms ?? IdTokenOptions.SigningAlgValuesSupported` and fail if no configured credential satisfies the effective set.
- **D10.** Credential rotation guide: when and how to register a second `IClientSecret` during a rollover window, the maximum of two active shared-secret credentials, the requirement that authenticators try all matching credentials, and the recommendation to remove the old credential once in-flight tokens have expired.
- **D11.** `EnableZkdErrorCodes` operator guidance — even with the §7 non-disclosure binding, richer diagnostics give attackers more signal in aggregate. Document that operators should treat the flag as confidential-clients-only or trusted-tenant-only by default; reserve `zkd_error` codes for confidential clients with a legitimate diagnostic need.

---

## Rejected Alternatives

- **`IReadOnlyDictionary<string, IClientRegistration>`** — forces in-memory materialisation of all clients; no async I/O; leaks enumeration. `IClientRepository` with `FindByClientIdAsync` is async-native and encapsulated.
- **Strings for all per-client vocabularies** — erases compile-time safety for `GrantType`/`ResponseType`/`ResponseMode`/`PromptValue` without buying extensibility (new values require framework changes). `AllowedTokenEndpointAuthMethods` stays `string` because `IClientAuthenticator` is a genuine open extension point.
- **`IClientSecretHasher` as `token_endpoint_auth_method` extension point** — hashers have no request context and cannot declare method strings for startup validation. `IClientAuthenticator` is the request-aware extension point.
- **`CanHandle(context)` as the *only* support declaration** — would require synthetic HTTP requests for startup coverage validation. The §4 design pairs `AuthenticationMethods` (static, for coverage) with `CanHandle` (dynamic, for dispatch): one static declaration for what the authenticator *can* produce, one runtime call for what *this* request actually carries. Each handles the question it's well-suited for.
- **Composite-side request-shape sniffing (rejected during review)** — an earlier §4 draft had `CompositeClientAuthenticator` hard-code "`Authorization: Basic` → `client_secret_basic`, `client_secret` form field → `client_secret_post`, otherwise → `none`". That moved positive-evidence detection responsibility to the composite, defeating the extension point: a new method like `tls_client_auth` would have required modifying the composite to inspect `HttpContext.Connection.ClientCertificate`. The current design delegates credential-bearing detection to authenticators via `CanHandle`, leaving the composite with no method-specific knowledge for extensible methods.
- **`PublicClientAuthenticator` as a normal `CanHandle` participant (rejected during re-review)** — `none` is absence of client authentication material, not positive evidence. In an extensible system, a public-client authenticator cannot know every possible custom mechanism; with `tls_client_auth`, it could return `none` while the TLS authenticator also returns `tls_client_auth`, causing a false multi-mechanism rejection. The current design reserves `none` to the composite fallback after every credential-bearing authenticator declines, and forbids authenticators from declaring or returning `none`.
- **Three-valued `Valid` / `NotValid` / `NoResult` outcome (rejected during review)** — `NoResult` modelled "not my request, try next" for a chain-of-responsibility dispatch. With `CanHandle` filtering the candidate set before any `AuthenticateAsync` call, the chain-of-responsibility shape disappears: at most one authenticator runs per request, and the result is a binary `Authenticated` flag.
- **`string? ClientSecret` on `IClientRegistration`** — ambiguous plaintext vs hash; pushes fixed-time comparison to every custom implementation; sample-code trap. Replaced by the `IClientCredential`/`IClientSecretHasher` split.
- **Service reference (`IClientSecretVerifier`) on `IClientRegistration`** — conflates data and behaviour; hostile to ORM mapping; forces every entity to carry a service reference.
- **Single `string Algorithm` discriminator on `IClientSecret`** — forces nullable fields for algorithm-specific parameters; central switch-based dispatch; modifications required for each new algorithm. Type-hierarchy (`secret is TSecret`) avoids the switch entirely.
- **Sealed record as sole representation** — forces mapping from consumer entity type into framework type on every lookup; interface allows zero-allocation direct implementation.
- **Separate public/confidential types** — discriminated-union return from `IClientRepository`; added complexity without proportionate safety gain given the declared `IsPublic` and startup consistency check.
- **`fragment` response mode** — serves only the implicit flow (removed in OAuth 2.1). Intentionally unsupported; rejected regardless of `AllowedResponseModes`.
- **Dynamic client registration (RFC 7591) for v1** — significantly increases scope and attack surface. The v1 abstractions are decorator-compatible with a future `ZeeKayDa.Auth.DynamicClients` package; see §10.
- **Abstract base class** — constrains implementors to single inheritance; interface is the idiomatic .NET choice.

---

## Consequences

### Positive

- Custom repositories return their own entity types with no framework mapping allocation on the hot path.
- Fail-closed redirect URI scheme allowlist: future browser URI schemes cannot accidentally become valid redirect targets without an explicit framework change.
- ORM-friendly credential model: flat columns, `[NotMapped]` projection to `IClientSecret`; no polymorphic owned-type acrobatics.
- New hashing algorithms drop in without framework changes: sub-interface + record + `ClientSecretHasher<T>` + `AddSecretsHasher<T>()`.
- `IClientAuthenticator` open extension point: new auth methods (e.g. `tls_client_auth`) via custom implementation plus explicit `TokenEndpoint.AuthMethodsSupported` configuration; startup validation guarantees coverage without over-advertising disabled methods.
- `Credentials` list enables credential rotation (maximum two active secrets during rollover) without a protocol change.
- `AllowedPromptValues` empty-default is forward-compatible when new `PromptValue` members are added.
- Timing oracle correctly scoped: `PadTiming()` fires only for non-default hashers, and shared-secret failure paths pad to a fixed two-credential budget so a rotation window does not reveal known clients.
- PKCE unconditionally enforced — no escape hatch to a weaker configuration.
- `zkd_error` non-disclosure constraint prevents client enumeration via extended error codes.

### Negative / Trade-offs

- Custom repositories bypass registration-time validation; they own the equivalent validation responsibility.
- `AddInMemoryClients` is additive — multiple calls accumulate registrations. The list is snapshot-frozen at DI construction time; order of registration does not matter beyond duplicate `client_id` detection (which throws).
- Multiple-hasher deployments require explicit `isDefault: true`; ambiguity is a startup failure, not a silent coin flip.
- `CompositeClientSecretHasher` registered as a concrete type to avoid self-injection recursion; consumers must not expose it as `IClientSecretHasher`.
- `CompositeClientSecretHasher` pre-computes a PBKDF2 dummy secret at startup (~600 ms one-time cost; intentional).
- Shared-secret authentication failures intentionally cost up to 2× the default hasher to avoid timing differences during credential rotation.
- Dynamic client registration deferred; `ZeeKayDa.Auth.DynamicClients` decorator pattern is the planned forward path.
- Migrating from a `string?`-based or verifier-on-registration prototype requires replacing `ClientSecret` with `Credentials` and adopting the hasher split. Acceptable because no consumer code has been written against the v1 interface.

---

## Spec References

| Spec | Section | Relevance |
|---|---|---|
| RFC 6749 | §2, §3.1.2, §4.1.2.1 | Client types, redirect URI requirements, `invalid_scope` |
| RFC 9700 | §2.1, §2.1.1, §2.1.2 | Redirect URI exact match, PKCE mandatory, PAR considerations |
| RFC 8252 | §7.1, §7.3, §8.3 | Private-use URI scheme, loopback port exception, `localhost` |
| RFC 7591 | (whole doc) | Dynamic client registration — out of scope for v1 |
| RFC 9126 | (whole doc) | Pushed Authorization Requests (PAR) — deferred to v2 |
| RFC 7515 | §4.1.1 | JWS `alg` — vocabulary for `AllowedSigningAlgorithms` |
| OIDC RP-Initiated Logout 1.0 | §2 | `post_logout_redirect_uri` / `PostLogoutRedirectUris` |
| OIDC Core 1.0 | §3.1.2.1, §3.1.3.7 | `prompt` parameter values, ID token `alg` matching |
| OAuth 2.1 draft | §7, §7.6 | Implicit/ROPC flows removed, PKCE mandatory |

> Spec section numbers consulted against the IETF drafts published as of 2026-06-08. The OAuth 2.1 draft is unstable; section numbers may shift between revisions and should be resolved against the revision current at that date when ground-truthing this ADR.

---

## Revision history

- **2026-06-07** — Initial draft through architect/security review acceptance pass. Established `IClientRepository`, redirect URI validation, scope intersection, PKCE-mandatory behaviour, `IClientSecret`/`IClientSecretHasher` split, `IClientAuthenticator`, timing constraints, `VerifyUnknownClientForTimingOnly`, `PromptValue`/`TokenEndpointAuthMethods` constants.
- **2026-06-08 (compact revision)** — Replace `IClientSecret? ClientSecret` with `IReadOnlyList<IClientCredential> Credentials`; `IClientSecret` gains `IClientCredential` base; `IClientAuthenticator` chain-of-responsibility dispatch formalised with three-result `ClientAuthenticationOutcome` enum; fix `PadTiming()` to fire only for non-default hashers; add `zkd_error` enumeration non-disclosure constraint; fix `AllowedPromptValues` default to empty set; add ordinal comparison rule for `AllowedTokenEndpointAuthMethods`; add `IJwksCredential` to v2 deferred list; add null-guard requirement on `ClientSecretAuthenticator`; document startup PBKDF2 cost; reclassify `TokenEndpointAuthMethod` as an open extension point and amend ADR 0002 / ADR 0003 accordingly; compact from ~2400 lines to ~500 lines.
- **2026-06-08 (architect/security review fixes)** — Change discovery to advertise only configured `TokenEndpoint.AuthMethodsSupported`; require exact requested-method dispatch; reject multiple client auth mechanisms; add server/client/authenticator subset validation; define fixed two-credential timing budget for shared-secret failures; specify ordinal client ID semantics, auth-method string hygiene, log/metric non-disclosure, and the `IInMemoryClientRegistrationBuilder` API.
- **2026-06-08 (accepted)** — Architect and security sign-off received (APPROVE-WITH-NITS); status flipped to Accepted. Non-blocking nits tracked as follow-ups against the D1–D10 docs deliverables and forthcoming implementation/token-endpoint issues.
- **2026-06-08 (validator extraction + enum removal)** — Add §6.1 introducing `IClientRegistrationValidator` so every repository implementation calls the same rule set at the moment that fits its lifecycle (in-memory at startup; custom DB/DCR at write time, or first read for read-mostly stores). Removes the implicit "in-memory is the only validated path" duplication risk. Strictly additive; runtime fail-closed defences in §4 and §7 unchanged. Update §6, §9, and D1 accordingly. Also remove the `TokenEndpointAuthMethod` enum outright (previously "may survive as a client-side deserialization helper") — strings carry the vocabulary end-to-end; tighten the ADR 0002 / ADR 0003 amendment notes to say "removed" rather than "reclassified".
- **2026-06-08 (review nits)** — Apply post-acceptance nits from architect/security review: raise PBKDF2 minimum to 600,000 to match OWASP (§3.3); add `IReadOnlySet<string>` comparer-trust invariant (§1); add `Pbkdf2ClientSecret` buffer-ownership note (§3.1); add accepted public-client timing residual (§3.4); require non-empty `AllowedTokenEndpointAuthMethods` for confidential clients and warn on advertised-but-unused `"none"` (§6); add coverage-validator layering note (§4); add `code_verifier` to log-never list and fragment-rejection binding constraint (§7); expand D5 with percent-encoding, IPv6, `localhost`-substring, and incoming-fragment coverage; add D11 for `EnableZkdErrorCodes` operator guidance (§11); pin OAuth 2.1 draft consultation date (§11 spec table).
- **2026-06-08 (authenticator self-dispatch)** — Replace composite-side request sniffing with `IClientAuthenticator.CanHandle(context, out string? method)` so authenticators detect their own requests. Composite no longer hard-codes method strings, making `tls_client_auth` and other extensions drop-in. Collapse `ClientAuthenticationOutcome` from three-valued (`Valid`/`NotValid`/`NoResult`) to two-valued (`Authenticated` bool) — `NoResult`'s "try next" role is now handled by `CanHandle` filtering before any `AuthenticateAsync` call. Allowlist check moves to before `AuthenticateAsync` to avoid unnecessary crypto; the per-client method list is not a secret, so fail-fast is acceptable. Update Rejected Alternatives accordingly.
- **2026-06-08 (authenticator integrity checks)** — Add startup invariant that every method string has exactly one authenticator owner (ambiguous ownership now fails at startup rather than misdiagnosing as multi-mechanism at runtime). Add runtime check that `CanHandle`'s returned method is a member of that authenticator's own `AuthenticationMethods` (defends against a buggy `CanHandle` returning an undeclared method that would otherwise bypass the startup coverage check).
- **2026-06-08 (`none` fallback)** — Reserve `TokenEndpointAuthMethods.None` to the composite fallback instead of modelling it as `PublicClientAuthenticator`. Credential-bearing authenticators own positive request evidence; `none` is chosen only after all of them decline. Startup validation now forbids authenticators from declaring `none`. This fixes the custom-method collision where `PublicClientAuthenticator` could incorrectly return `none` for a request containing auth material it did not know how to detect (for example `tls_client_auth`).
- **2026-06-11 (hasher infrastructure implementation fixes)** — Post-implementation review findings applied: (1) `PadTiming()` now uses the constant `DummyPresented` span rather than the attacker-controlled `presented` span, closing a potential timing-oracle widening against custom default hashers with input-length-dependent cost (security M1, §3.4); (2) `Pbkdf2ClientSecretHasher.VerifyCore` rejects stored credentials whose `Iterations` exceeds `MaxIterations` (2,000,000) and returns `false` with a warning, preventing CPU-bound DoS from a malformed credential store (§3.3); (3) `AddSecretsHasher<T>()` throws `InvalidOperationException` at registration time if the same hasher type is registered more than once (§9); (4) accepted timing residual: raising `Iterations` should be paired with credential rotation, as the unknown-client timing baseline diverges from old stored credentials until they are re-hashed (§3.4).
- **2026-06-11 (`CreateConfidential` signature amendment)** — Replace `(IClientSecretHasher hasher, string clientSecret, ...)` with `(IClientCredential credential, ...)` in `ClientRegistration.CreateConfidential`. Rationale: `ClientRegistration` is a pure value object; mixing a service dependency (`IClientSecretHasher`) into the factory couples data construction to hashing infrastructure. The caller hashes the secret and passes the resulting `IClientCredential` directly. `IInMemoryClientRegistrationBuilder.AddConfidential` (§6) remains the primary DI-friendly path and retains hashing responsibility at the builder layer. The `IClientSecretHasher` parameter is retained in `IClientSecretHasher` itself and in the builder; only the `ClientRegistration` factory is affected.
- **2026-06-13 (`ClientAuthenticationResult.Error` removed)** — The `Error` property is dropped from `ClientAuthenticationResult`. RFC 6749 §5.2 mandates exactly `invalid_client` for all client authentication failures at the token endpoint; there is no spec-permitted scenario in which a different error code is appropriate, so the property carried no real information. The token endpoint hardcodes `invalid_client` in its error response and does not read from the result object. The binary `Valid()`/`NotValid()` shape is the correct, spec-faithful model; `Error` was YAGNI. Dispatch rules in §4 and the `none` fallback in §6 already describe all failure paths returning `invalid_client` unconditionally.
- **2026-06-13 (§4 amended forward to match implementation)** — Three implementation-time divergences from the accepted §4 spec are recorded here so the ADR is the authoritative source for downstream implementers: (1) `TokenRequestContext`/`ClientAuthenticationContext` split — the draft had a single nullable-client context; the implementation introduces `TokenRequestContext` (no client, used in `CanHandle`) as a base class and `ClientAuthenticationContext : TokenRequestContext` (non-null `Client`, used in `AuthenticateAsync`), eliminating an entire null-dereference class from custom implementations; (2) `method` parameter removed from `AuthenticateAsync` — the draft passed the matched method string back into `AuthenticateAsync` so multi-method authenticators could branch without re-derivation; the implementation drops the parameter and requires re-derivation via the same cheap shape check used in `CanHandle`; (3) `Form` and `Headers` as required init properties on `TokenRequestContext` — access via `HttpRequest.Form` is synchronous and throws on non-form content types (both attacker-controllable); pre-reading at context-construction time and exposing both as `init` properties gives all authenticators a consistent immutable snapshot. The code is not reverted; the ADR is amended forward. Dispatch rules #1, #5, and #6 updated to match; §9 package table updated to include `TokenRequestContext`.
