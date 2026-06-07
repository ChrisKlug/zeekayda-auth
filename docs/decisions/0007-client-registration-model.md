# ADR 0007 — Client Registration Model

**Status:** Draft  
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

### 1a. Enum vs string for per-client vocabularies

- **Enum** when a new value requires framework-side implementation: `GrantType`, `ResponseType`, `ResponseMode`, `PromptValue`.
- **`IReadOnlySet<string>`** when a public extension point carries a new value end-to-end without core changes: `AllowedTokenEndpointAuthMethods` (any `IClientAuthenticator` can introduce a new method such as `tls_client_auth`). Membership checks MUST use `StringComparer.Ordinal`.
- `TokenEndpointAuthMethods` constants class (`ClientSecretBasic`, `ClientSecretPost`, `None`) eliminates magic strings for ZeeKayDa-handled values.
- The existing `TokenEndpointAuthMethod` *enum* (for discovery metadata advertisement) is kept separate from `AllowedTokenEndpointAuthMethods`; the two are not unified.

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

Validation lives in `InMemoryClientRepository`, not the record constructor (keeps the record a pure value object; tests can construct invalid instances to exercise validators).

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

**Credential rotation:** multiple `IClientSecret` entries in `Credentials` are valid simultaneously during a rollover window. Authenticators MUST try ALL `client.Credentials.OfType<TCredential>()` before returning `NotValid`.

**Deferred to v2:** `IJwksCredential : IClientCredential` (for `private_key_jwt`; carries `JwksUri` or inline JWKS). This will be the first non-secret `IClientCredential` subtype.

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
| Minimum iterations | 100,000 (constructor-enforced) |
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
}
```

**Timing oracle.** `PadTiming()` (runs `_default.Verify(_dummySecret, _dummyPresented)`) fires only when the matched hasher is NOT the default:

```csharp
if (!result && !ReferenceEquals(h, _default))
    PadTiming();
```

Rationale: in standard deployments (single PBKDF2 hasher = the default), both the unknown-client path and the known-client-wrong-secret path already pay 1× PBKDF2. `PadTiming()` only adds work when a faster custom hasher matched — preventing that hasher from reopening a timing oracle. Rate limiting is the primary enumeration defence; `VerifyUnknownClientForTimingOnly` equalises the unknown-client path regardless.

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

### 4. `IClientAuthenticator` — chain-of-responsibility dispatch

```csharp
namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

public interface IClientAuthenticator
{
    /// Method strings this authenticator handles (ordinal comparison).
    IReadOnlySet<string> AuthenticationMethods { get; }

    ValueTask<ClientAuthenticationResult> AuthenticateAsync(
        ClientAuthenticationContext context, CancellationToken cancellationToken);
}

public sealed class ClientAuthenticationContext
{
    public required HttpContext HttpContext { get; init; }
    public required IClientRegistration? Client { get; init; }
    public required string ClientId { get; init; }
    public required string? RequestedAuthMethod { get; init; }
    public required IFormCollection Form { get; init; }
    public required IHeaderDictionary Headers { get; init; }
}

public sealed record ClientAuthenticationResult
{
    public required ClientAuthenticationOutcome Outcome { get; init; }
    public string Error { get; init; } = "invalid_client";

    public static ClientAuthenticationResult Valid();
    public static ClientAuthenticationResult NotValid();
    public static ClientAuthenticationResult NoResult();
}

public enum ClientAuthenticationOutcome { Valid, NotValid, NoResult }
```

**Dispatch rules (`CompositeClientAuthenticator`):**

- Only authenticators whose `AuthenticationMethods` intersects `client.AllowedTokenEndpointAuthMethods` are invoked (dispatch filter AND security constraint). All membership checks use `StringComparer.Ordinal`.
- Ownership is determined from HTTP request shape (e.g. `Authorization: Basic` header → `client_secret_basic`).
- `Valid` → stop, authenticated. `NotValid` → stop, return `invalid_client`. `NoResult` → not my request, try next.
- Chain exhausted with all `NoResult` → unauthenticated, return `invalid_client`.

**Rotation:** when an authenticator owns a request, it MUST try ALL `client.Credentials.OfType<TCredential>()` before returning `NotValid`.

**Null guard:** `ClientSecretAuthenticator` MUST check `credentials.FirstOrDefault() is null` and return `NotValid` (not throw) when the client has no matching credentials.

**v1 built-in authenticators:**

- `PublicClientAuthenticator` — handles `none`; fails if a secret is presented for a public client.
- `ClientSecretAuthenticator` — handles `client_secret_basic` and `client_secret_post`; delegates stored-secret verification to `CompositeClientSecretHasher`. (`client_secret_post` supported for compatibility; should be enabled only when needed as request bodies are more likely to appear in logs.)

**Startup validation:** every `AllowedTokenEndpointAuthMethods` value across all clients MUST be present in at least one registered `IClientAuthenticator.AuthenticationMethods`. Missing coverage is a `ValidateOptionsResult.Fail(...)` at startup.

### 5. Redirect URI validation

Rules enforced at registration time (`InMemoryClientRepository`) and request time (belt-and-suspenders for custom repositories):

1. **Exact ordinal string match** — enumerate registered strings with `StringComparer.Ordinal`; do not trust the `IReadOnlySet` instance's own comparer.
2. **RFC 8252 §7.3 loopback-port exception** — port component ignored for loopback hosts at match time only.
3. **No fragment** — `Uri.Fragment` non-empty → rejected (RFC 6749 §3.1.2).
4. **No userinfo** — `Uri.UserInfo` non-empty → rejected.
5. **No `.`/`..` path segments** — ambiguous canonicalisation.
6. **Scheme allowlist** — `https` (any host); `http` (loopback only); a private-use scheme that contains `.` and is not in the forbidden list (`javascript`, `data`, `file`, `vbscript`, `about`, `blob`, `ws`, `wss`, `ftp`, `mailto`, `tel`). All other schemes rejected.
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

`InMemoryClientRepository` validates all registrations at construction time; failures throw `ArgumentException` before the host starts accepting requests.

**No default `IClientRepository` is registered** by `AddZeeKayDaAuth`; its absence is caught by `IValidateOptions<ZeeKayDaAuthOptions>` with `ValidateOnStart()`.

**Consistency rule at registration time:**

| `IsPublic` | `Credentials.Count` | `AllowedTokenEndpointAuthMethods` |
|---|---|---|
| `true` | `0` | exactly `{ "none" }` |
| `false` | `> 0` | MUST NOT contain `"none"` |

**Additional registration-time checks:**

- `ClientId` matches `[A-Za-z0-9_\-.]+`, max 200 chars.
- Confidential clients: `CompositeClientSecretHasher.Verify(credential, ReadOnlySpan<char>.Empty)` MUST return `false` for every `IClientSecret` in `Credentials` (defence-in-depth against a broken hasher that accepts empty input).
- `AllowedSigningAlgorithms` non-null ⇒ non-empty (shape check); subset check against `IdTokenOptions.SigningAlgValuesSupported` runs via `IValidateOptions<…>` at host startup (best-effort for in-memory clients; custom repositories must enforce their own subset validation).
- `AllowedScopes` contains no empty/whitespace entries.
- `Enum.IsDefined` for all enum-typed sets (guards against `(GrantType)999`-style casts).
- No duplicate `client_id` within the repository.

**ID-token signing at issuance:** effective set = `client.AllowedSigningAlgorithms ?? IdTokenOptions.SigningAlgValuesSupported`. Issuance MUST fail if no configured signing credential satisfies the effective set. Startup validation is best-effort early warning; issuance time is the security boundary.

**DI wiring:** `AddInMemoryClients(IEnumerable<IClientRegistration>)` uses `Replace` semantics (last-call-wins, mirrors `AddInMemoryScopes`). `AddSecretsHasher<T>(bool isDefault = false)` is the second builder extension.

### 7. Client enumeration mitigation

- **Token endpoint:** `invalid_client` for both unknown `client_id` and wrong credential. `error_description` MUST NOT include the `client_id`.
- **`zkd_error` non-disclosure constraint (binding):** when `EnableZkdErrorCodes` is `true`, the `zkd_error` value for `invalid_client` MUST NOT distinguish "unknown client_id" from "wrong credential". Any token-endpoint ADR or implementation that adds `zkd_error` codes MUST respect this constraint.
- **Timing:** `CompositeClientSecretHasher.VerifyUnknownClientForTimingOnly(presented)` pads the unknown-client path (always returns failure semantics after performing default-hasher work). `PadTiming()` pads the known-client failure path only when a non-default hasher matched (§3.4).
- **Authorization endpoint:** unknown `client_id` fails before any redirect; the generic error page MUST NOT echo the `client_id` unencoded.
- **Rate limiting** is the operator's responsibility; timing uniformity is necessary but not sufficient to defeat a sustained enumeration attempt.

**Binding forward constraints on the token endpoint (for the future token-endpoint ADR):**

1. Token endpoint client authentication MUST delegate to `CompositeClientAuthenticator`, which dispatches to a registered `IClientAuthenticator`. For shared-secret methods, `ClientSecretAuthenticator` MUST delegate stored-secret verification to `CompositeClientSecretHasher.Verify(...)`. **The framework MUST NOT compare secret strings itself** — all comparisons go through a hasher so fixed-time equality is centrally guaranteed.
2. `IsPublic == true` (equivalently `Credentials.Count == 0`) means "public client" — any presented `client_secret` MUST cause rejection with `invalid_client`.
3. The unknown-client path MUST call `CompositeClientSecretHasher.VerifyUnknownClientForTimingOnly(presented)` so its work factor matches the default hasher's success path.

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
| `IClientRepository`, `InMemoryClientRepository` | `ZeeKayDa.Auth` |
| `TokenEndpointAuthMethods`, `PromptValue`, `GrantType`, `ResponseType`, `ResponseMode` | `ZeeKayDa.Auth` |
| `IClientAuthenticator`, `ClientAuthenticationContext`, `ClientAuthenticationResult`, `ClientAuthenticationOutcome` | `ZeeKayDa.Auth.AspNetCore` |
| `PublicClientAuthenticator`, `ClientSecretAuthenticator`, `CompositeClientAuthenticator` (internal) | `ZeeKayDa.Auth.AspNetCore` |
| `AddInMemoryClients`, `AddSecretsHasher<T>` | `ZeeKayDa.Auth.AspNetCore` |

### 10. Forward compatibility with RFC 7591 dynamic client registration

Dynamic registration is out of scope for v1, but the v1 abstractions are deliberately shaped so a future `ZeeKayDa.Auth.DynamicClients` package can layer on without breaking changes:

- A future `DynamicClientRepository` will be a **decorator** that wraps an internal mutable `IWritableClientRepository` (handling persistence) and exposes the RFC 7591 `/register` endpoint. The read-only `IClientRepository` surface in this ADR is the read side of that future split.
- Policy is kept separate from storage: a separate `IDynamicClientRegistrationPolicy` interface will gate which metadata fields a self-registering client may set, what scopes/grant types it may request, and any rate limiting. Keeping policy out of the repository keeps the policy decisions testable in isolation and ensures the static-registration guarantees this ADR establishes (validation, consistency rules, redirect URI rules) are not eroded by the dynamic-registration code path — the dynamic path runs the same `InMemoryClientRepository`-style validation before persisting.
- No changes to `IClientRegistration`, `IClientCredential`, or the hasher contracts are anticipated; dynamic registration adds a new write surface, not a new data shape.

### 11. Documentation requirements

The following docs deliverables fall out of this ADR and must be tracked in the docs follow-up PR (one issue per item, or a single tracking issue with checkboxes):

- **D1.** Custom `IClientRepository` implementer's contract — parametrised lookup (no SQL concatenation), `null`-not-throw rule for unknown clients, the registration validation rules the implementer owns, and an example skeleton.
- **D2.** Storing client credentials across ORMs — worked examples for EF Core (`IPbkdf2ClientSecret` via flat `Pbkdf2Iterations` / `Pbkdf2Salt` / `Pbkdf2Hash` columns projected through `[NotMapped]`), NHibernate (component mapping), and Dapper (query projection). Includes a guide to implementing a new hasher: define the sub-interface, define the record, subclass `ClientSecretHasher<TSecret>`, register with `AddSecretsHasher<T>()` (with `isDefault: true` if it should be the create-time default). Recommends against storing plaintext secrets at rest.
- **D3.** Every sample-code block that uses a plaintext secret literal (e.g. `clientSecret: "s3cr3t"` in a `CreateConfidential` call) must carry a prominent warning that the literal is illustrative only and unsuitable for production.
- **D4.** A note on `localhost` vs `127.0.0.1` citing RFC 8252 §8.3 and explaining why the framework emits an advisory warning on `localhost`.
- **D5.** `SECURITY.md` (or `docs/security/redirect-uri-validation.md`) capturing the scheme allowlist, loopback-port exception, userinfo prohibition, exact-ordinal matching requirement (enumerate registered strings; do not trust the `IReadOnlySet` comparer), the edge-case matrix from §5, and the threat model that motivates each rule.
- **D6.** An `AllowedResponseModes` doc note explaining that `fragment` is intentionally unsupported, pointing at the Rejected Alternatives entry.
- **D7.** A PKCE-mandatory FAQ entry citing RFC 9700 §2.1.1 and OAuth 2.1 §7.6, explaining why there is no per-client `RequirePkce` opt-out.
- **D8.** A client-authentication extensibility note distinguishing `IClientAuthenticator` (token endpoint request authentication) from `IClientSecretHasher` (stored shared-secret creation/verification), warning that `client_secret_post` should be enabled only for compatibility, and documenting auth-method coverage validation.
- **D9.** A signing-algorithm enforcement note for custom repositories: startup subset validation is best-effort, but issuance MUST use `client.AllowedSigningAlgorithms ?? IdTokenOptions.SigningAlgValuesSupported` and fail if no configured credential satisfies the effective set.
- **D10.** Credential rotation guide: when and how to register a second `IClientSecret` during a rollover window, the requirement that authenticators try all matching credentials, and the recommendation to remove the old credential once in-flight tokens have expired.

---

## Rejected Alternatives

- **`IReadOnlyDictionary<string, IClientRegistration>`** — forces in-memory materialisation of all clients; no async I/O; leaks enumeration. `IClientRepository` with `FindByClientIdAsync` is async-native and encapsulated.
- **Strings for all per-client vocabularies** — erases compile-time safety for `GrantType`/`ResponseType`/`ResponseMode`/`PromptValue` without buying extensibility (new values require framework changes). `AllowedTokenEndpointAuthMethods` stays `string` because `IClientAuthenticator` is a genuine open extension point.
- **`IClientSecretHasher` as `token_endpoint_auth_method` extension point** — hashers have no request context and cannot declare method strings for startup validation. `IClientAuthenticator` is the request-aware extension point.
- **`CanHandle(context)` as the only authenticator support declaration** — would require synthetic HTTP requests for startup coverage validation. `AuthenticationMethods` is the static declaration.
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
- `IClientAuthenticator` open extension point: new auth methods (e.g. `tls_client_auth`) via custom implementation without core changes; startup validation guarantees coverage.
- `Credentials` list enables credential rotation (two active secrets during rollover) without a protocol change.
- `AllowedPromptValues` empty-default is forward-compatible when new `PromptValue` members are added.
- Timing oracle correctly scoped: `PadTiming()` fires only for non-default hashers; standard single-PBKDF2 deployments pay exactly 1× PBKDF2 on every failure path.
- PKCE unconditionally enforced — no escape hatch to a weaker configuration.
- `zkd_error` non-disclosure constraint prevents client enumeration via extended error codes.

### Negative / Trade-offs

- Custom repositories bypass registration-time validation; they own the equivalent validation responsibility.
- `AddInMemoryClients` Replace semantics: a second call silently replaces the first (intentional for tests; can be surprising in production).
- Multiple-hasher deployments require explicit `isDefault: true`; ambiguity is a startup failure, not a silent coin flip.
- `CompositeClientSecretHasher` registered as a concrete type to avoid self-injection recursion; consumers must not expose it as `IClientSecretHasher`.
- `CompositeClientSecretHasher` pre-computes a PBKDF2 dummy secret at startup (~600 ms one-time cost; intentional).
- Dynamic client registration deferred; `ZeeKayDa.Auth.DynamicClients` decorator pattern is the planned forward path.
- Migrating from a `string?`-based or verifier-on-registration prototype requires replacing `ClientSecret` with `Credentials` and adopting the hasher split. Acceptable because the ADR is still **Draft** and no consumer code has been written against the v1 interface.

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

---

## Revision history

- **2026-06-07** — Initial draft through architect/security review acceptance pass. Established `IClientRepository`, redirect URI validation, scope intersection, PKCE-mandatory behaviour, `IClientSecret`/`IClientSecretHasher` split, `IClientAuthenticator`, timing constraints, `VerifyUnknownClientForTimingOnly`, `PromptValue`/`TokenEndpointAuthMethods` constants.
- **2026-06-07 (compact revision)** — Replace `IClientSecret? ClientSecret` with `IReadOnlyList<IClientCredential> Credentials`; `IClientSecret` gains `IClientCredential` base; `IClientAuthenticator` chain-of-responsibility dispatch formalised with three-result `ClientAuthenticationOutcome` enum; fix `PadTiming()` to fire only for non-default hashers; add `zkd_error` enumeration non-disclosure constraint; fix `AllowedPromptValues` default to empty set; add ordinal comparison rule for `AllowedTokenEndpointAuthMethods`; add `IJwksCredential` to v2 deferred list; add null-guard requirement on `ClientSecretAuthenticator`; document startup PBKDF2 cost; compact from ~2400 lines to ~500 lines.
