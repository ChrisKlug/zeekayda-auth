# ADR 0007 — Client Registration Model

**Status:** Draft  
**Date:** 2026-06-07

---

## Context

ZeeKayDa.Auth is an OpenID Connect / OAuth 2.x identity provider framework. Every authorization
request arrives with a `client_id`. Before the framework can validate the request, issue a code, or
produce a discovery document with accurate metadata, it must be able to answer: "Is this client
known to me? What is it allowed to do?"

This ADR resolves the data model and the lookup abstraction for registered clients. Several forces
are at play:

1. **Static vs dynamic registration.** RFC 7591 defines a dynamic client registration protocol. For
   the initial version of ZeeKayDa.Auth, dynamic registration is out of scope. All clients are
   registered at startup — either in-memory for simple deployments or via a custom store for
   production deployments backed by a database.

2. **Type system representation.** The client registration shape needs to be representable in .NET
   in a way that is immutable, extensible, and safe to pass through the framework's internal
   pipeline.

3. **Public vs confidential clients.** RFC 6749 §2.1 distinguishes clients that can maintain
   the confidentiality of their credentials (confidential) from those that cannot (public, e.g.
   SPA, native app). The distinction governs which validation rules apply at request time. The
   type system must represent this distinction clearly.

4. **Redirect URI security.** RFC 9700 §2.1 (OAuth 2.0 Security BCP) mandates exact-string
   comparison of redirect URIs and prohibits HTTP redirect URIs except for loopback addresses
   (RFC 8252 §7.3). Violating these rules is one of the most common OAuth 2.x vulnerabilities.
   The framework must enforce them as early as possible — ideally at startup — so a misconfigured
   client fails loudly rather than silently accepting a malicious redirect at runtime.

5. **Scope intersection.** ADR 0005 §7 established that `IConsentInteraction.GrantAsync`
   intersects granted scopes with the client's `AllowedScopes`. This rule has its roots in the
   client registration model: the client's permitted scopes must be stored somewhere
   authoritative, and the client repository is that place.

6. **Layering.** `ZeeKayDa.Auth` (core) has zero knowledge of ASP.NET Core. All abstractions
   owned by the client registration subsystem must live in the core package if they are needed by
   the framework's internal pipeline. Only DI wiring extensions belong in
   `ZeeKayDa.Auth.AspNetCore`.

7. **OAuth 2.1 alignment.** The framework targets OAuth 2.1 forward-compatibility (see
   [draft-ietf-oauth-v2-1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)). Key
   consequences: implicit flow is removed, ROPC flow is removed, and PKCE is mandatory for all
   clients (including confidential clients). No per-client opt-out of PKCE is provided.

---

## Decision

### 1. `IClientRegistration` — interface, not record or abstract class

Client registration is represented as an **interface** in `ZeeKayDa.Auth`, not a concrete record
or abstract class.

```csharp
namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Represents a registered OAuth 2.x / OIDC client.
/// </summary>
public interface IClientRegistration
{
    /// <summary>The unique client identifier (<c>client_id</c>).</summary>
    string ClientId { get; }

    /// <summary>
    /// The stored client secret credential, or <see langword="null"/> for public clients.
    /// This is pure data (no behaviour) — verification and creation are delegated to
    /// <see cref="IClientSecretHasher"/> implementations resolved from DI. See §3.
    /// </summary>
    /// <remarks>
    /// The framework NEVER stores or compares plaintext secrets directly. The token-endpoint
    /// pipeline asks the framework-internal <c>CompositeClientSecretHasher</c> to verify a
    /// presented plaintext against this property's value; the composite dispatches to the
    /// registered <see cref="IClientSecretHasher"/> whose <see cref="IClientSecretHasher.CanHandle"/>
    /// returns <see langword="true"/> for the concrete type.
    /// </remarks>
    IClientSecret? ClientSecret { get; }

    /// <summary>
    /// Declares whether this is a public client. MUST be <see langword="true"/> if and only if
    /// <see cref="ClientSecret"/> is <see langword="null"/> and
    /// <see cref="AllowedTokenEndpointAuthMethods"/> is exactly
    /// <c>{ TokenEndpointAuthMethods.None }</c>; this consistency rule is enforced at registration
    /// time (§6) with <see cref="ZeeKayDaConfigurationException"/> on violation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This property is a **declared** member, not a default interface method. The earlier draft
    /// derived it from <c>ClientSecret is null</c>; that proved hostile to the same class of
    /// configuration bugs as <see cref="PostLogoutRedirectUris"/> (a custom implementor whose
    /// entity does not yet expose a secret column would silently appear public). Forcing the
    /// implementor to declare <see cref="IsPublic"/> surfaces the configuration intent at
    /// compile time.
    /// </para>
    /// <para>
    /// Public clients require PKCE on every authorization request (RFC 9700 §2.1.1). The
    /// framework enforces this unconditionally; there is no per-client override.
    /// </para>
    /// </remarks>
    bool IsPublic { get; }

    /// <summary>
    /// The pre-registered redirect URIs for this client. At least one URI must be
    /// present. Exact-string comparison is enforced at request time (RFC 9700 §2.1),
    /// subject to the loopback-port exception described in §4.
    /// </summary>
    IReadOnlySet<string> RedirectUris { get; }

    /// <summary>
    /// The set of post-logout redirect URIs registered for this client, used by the OIDC
    /// RP-Initiated Logout 1.0 end-session endpoint. Validation rules mirror
    /// <see cref="RedirectUris"/>: scheme allowlist (HTTPS, HTTP-on-loopback, RFC 8252 §7.1
    /// private-use), no fragment, no userinfo, no <c>.</c>/<c>..</c> path segments. The
    /// RFC 8252 §7.3 loopback-port exception applies at request-time match.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A non-DIM declared property is used deliberately: <see cref="PostLogoutRedirectUris"/>
    /// is pure data with no derivation from other members. A silent empty-set default would
    /// cause a custom <see cref="IClientRepository"/> implementor who forgets the property to
    /// register a client that silently rejects every end-session request — a hard-to-diagnose
    /// configuration bug. Forcing implementors to declare the property surfaces the
    /// configuration omission at compile time.
    /// </para>
    /// <para>
    /// Consumers whose clients have no post-logout redirect URIs must still pass an empty
    /// set explicitly, e.g. <c>new HashSet&lt;string&gt;(StringComparer.Ordinal)</c> or the
    /// collection-expression form <c>[]</c> target-typed to <c>IReadOnlySet&lt;string&gt;</c>.
    /// </para>
    /// </remarks>
    IReadOnlySet<string> PostLogoutRedirectUris { get; }

    /// <summary>
    /// The scopes this client is permitted to request. Scopes not in this set are
    /// silently dropped when computing the granted scope set (see §5 — scope intersection).
    /// </summary>
    IReadOnlySet<string> AllowedScopes { get; }

    /// <summary>
    /// The grant types this client is permitted to use at the token endpoint.
    /// Defaults to <c>{ <see cref="GrantType.AuthorizationCode"/> }</c> in
    /// <see cref="ClientRegistration"/>.
    /// </summary>
    /// <remarks>
    /// OAuth 2.1 removes the implicit and ROPC grant types. The framework will reject any
    /// token request whose grant type is not listed here. To receive refresh tokens, the
    /// client must explicitly include <see cref="GrantType.RefreshToken"/> in this set.
    /// </remarks>
    IReadOnlySet<GrantType> AllowedGrantTypes { get; }

    /// <summary>
    /// The response types this client is permitted to request at the authorization
    /// endpoint. Defaults to <c>{ <see cref="ResponseType.Code"/> }</c> in
    /// <see cref="ClientRegistration"/>.
    /// </summary>
    IReadOnlySet<ResponseType> AllowedResponseTypes { get; }

    /// <summary>
    /// The response modes this client is permitted to use. Defaults to
    /// <c>{ <see cref="ResponseMode.Query"/>, <see cref="ResponseMode.FormPost"/> }</c> in
    /// <see cref="ClientRegistration"/>.
    /// </summary>
    /// <remarks>
    /// <see cref="ResponseMode.Fragment"/> is intentionally never accepted by the
    /// request-time validator regardless of the client's allowed set (see Rejected
    /// Alternatives).
    /// </remarks>
    IReadOnlySet<ResponseMode> AllowedResponseModes { get; }

    /// <summary>
    /// The token-endpoint client authentication methods this client is permitted to use.
    /// Defaults to <c>{ <see cref="TokenEndpointAuthMethods.ClientSecretBasic"/> }</c> for
    /// confidential clients and <c>{ <see cref="TokenEndpointAuthMethods.None"/> }</c> for
    /// public clients (see <see cref="ClientRegistration"/>).
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is the only protocol-vocabulary property typed as <see cref="IReadOnlySet{T}"/>
    /// of <see cref="string"/>; all others (grant types, response types, response modes,
    /// prompt values) are enums. The reason — a third party can introduce a new auth method
    /// (e.g. <c>tls_client_auth</c>) end-to-end by supplying a custom
    /// <see cref="IClientSecretHasher"/> (paired with a custom <see cref="IClientSecret"/>
    /// sub-interface) without any framework code change — is documented in §1a. Reference
    /// the constants on <see cref="TokenEndpointAuthMethods"/> for the framework-recognised
    /// values to avoid magic strings.
    /// </para>
    /// <para>
    /// Distinct from the closed <see cref="TokenEndpointAuthMethod"/> enum, which serves
    /// discovery metadata advertisement (the closed set of methods this server implements).
    /// The two are deliberately not unified — see §1a.
    /// </para>
    /// </remarks>
    IReadOnlySet<string> AllowedTokenEndpointAuthMethods { get; }

    /// <summary>
    /// The <c>prompt</c> values this client is permitted to send. When non-empty, the
    /// framework rejects authorization requests whose <c>prompt</c> is not in this set.
    /// When empty, all OIDC Core-standard prompt values are permitted for this client.
    /// </summary>
    /// <remarks>
    /// Values are drawn from <see cref="PromptValue"/>, per OIDC Core 1.0 §3.1.2.1.
    /// </remarks>
    IReadOnlySet<PromptValue> AllowedPromptValues { get; }

    /// <summary>
    /// When <see langword="true"/>, ZeeKayDa includes the <c>zkd_error</c> extension
    /// parameter in error responses sent to this client. See ADR 0005 §11.
    /// </summary>
    bool EnableZkdErrorCodes { get; }

    /// <summary>
    /// The set of JWS signing algorithms this client accepts for ID tokens.
    /// <see langword="null"/> means "inherit from
    /// <c>IdTokenOptions.SigningAlgValuesSupported</c>" (the framework-wide default —
    /// typically <c>{<see cref="SigningAlgorithm.RS256"/>}</c>). A non-null value MUST be a
    /// non-empty subset of the globally configured set; this is verified at registration time
    /// (shape check) and at host startup (cross-options subset check). See §6 and §8.
    /// </summary>
    /// <remarks>
    /// A default interface member returning <see langword="null"/> is appropriate here
    /// because <see langword="null"/> has a precise semantic ("inherit global default") that
    /// is the correct behaviour for every custom <see cref="IClientRepository"/>
    /// implementation that does not explicitly opt in to per-client narrowing. This makes the
    /// property a non-breaking addition for existing implementations.
    /// </remarks>
    IReadOnlySet<SigningAlgorithm>? AllowedSigningAlgorithms => null;
}
```

**Why an interface, not a sealed record or abstract class?**

The primary use case for a custom `IClientRepository` implementation (see §6) is "I retrieve client
data from my own database and want to return my own entity type." An interface lets that entity
type implement `IClientRegistration` directly — no mapping step, no copying of data into a
separate framework object. A sealed record or abstract class would require every custom repository
to translate its own model into a framework type, adding allocation and impedance mismatch on the
hot path of every authorization request.

A sealed record as the only representation would also prevent future implementations from adding
computed properties derived from their own extended fields (e.g. a multi-tenant repository that
derives `AllowedScopes` from a tenant plan lookup).

An abstract class would constrain implementors to single inheritance — unnecessarily restrictive
for an entity type that the consumer already has in their domain model.

**Framework code consumes `IClientRegistration`, never `ClientRegistration`.** All internal
pipeline code (request validation, consent, token endpoint, …) takes its dependency on the
interface. This guarantees that customisations flow through the same framework branches as
the built-in record.

**`IsPublic` as a declared (non-DIM) member.** Earlier drafts modelled this as a default
interface method derived from `SecretVerifier is null`. The current design replaces the
verifier-on-registration with a pure-data `IClientSecret?` property (see §3) and promotes
`IsPublic` to a declared member that the consumer's entity must specify explicitly — for the
same reason `PostLogoutRedirectUris` is declared rather than DIM-defaulted: a silent default
("any implementor that forgets the property is public") would convert a configuration omission
into a security-relevant runtime behaviour change. The §6 consistency check
(`IsPublic ⇔ ClientSecret is null ⇔ AllowedTokenEndpointAuthMethods == { None }`) catches
declared-but-inconsistent registrations at startup.

**No per-client `RequirePkce` flag.** OAuth 2.1 mandates PKCE for all clients unconditionally.
Introducing a per-client `RequirePkce` toggle would create an escape hatch to a
less-secure configuration. The framework enforces PKCE on every authorization code request
regardless of client type. Any deployment that cannot support PKCE (e.g., a legacy client) is
out of scope for this framework.

**Deferred-to-v2 properties** — explicitly NOT on the v1 `IClientRegistration`:

- **Display metadata** — `ClientName`, `LogoUri`, `PolicyUri`, `TosUri` (OIDC Dynamic Client
  Registration §2). These become necessary when the consent UI driven by `IConsentInteraction`
  needs to render client identity to end users; v1 ships without a built-in consent UI and so does
  not need them on the core interface. Custom implementations are free to expose them on their own
  derived interfaces today; the framework will introduce them on `IClientRegistration` as default
  interface members (returning `null`) when the UI need arises — non-breaking for existing
  implementations.
- **`RequirePushedAuthorizationRequests`** (RFC 9126 PAR). Added when PAR is implemented; default
  interface member returning `false`. Per RFC 9700 §2.1.2 the appropriate default for confidential
  clients should be reconsidered at that point.
- **Token lifetime overrides** (e.g. `AccessTokenLifetime`, `RefreshTokenLifetime`) — per-client
  token TTL overrides will be expressed as `TimeSpan?` properties with `null` meaning "use the
  global default from `AuthorizationServerOptions`". Same non-breaking default interface method
  strategy applies.

### 1a. Why enums for closed protocol vocabularies, strings for open extension points

The choice between an enum and a `string` for per-client protocol-vocabulary fields turns on a
single question: **can a new value be supported without changes to ZeeKayDa framework code?**

- For `grant_type`, `response_type`, `response_mode`, and `prompt`, a new value (e.g.
  `urn:ietf:params:oauth:grant-type:device_code`, or JARM's `form_post.jwt` response mode)
  requires framework implementation — the AS must know how to honour it. The "open set"
  extensibility argument is therefore illusory; the type system gains nothing from `string`
  and loses compile-time enforcement. These four fields use enums:
  `GrantType`, `ResponseType`, `ResponseMode`, and the new `PromptValue` (see below).

- For `token_endpoint_auth_method`, a new value (e.g. `tls_client_auth`,
  `self_signed_tls_client_auth`) genuinely can be introduced without framework changes — a
  custom `IClientSecretHasher` (paired with a custom `IClientSecret` sub-interface) is a
  public extension point that lets a third party implement the verification logic end-to-end.
  Here the open-set argument applies, and `IReadOnlySet<string>` is the right choice. The
  framework ships a `TokenEndpointAuthMethods` constants class (below) so consumers
  reference the known values without magic strings.

Future per-client vocabularies must be evaluated against the same rule: **enum** if
framework changes are required to honour a new value, **`string` + a constants class** only
if a public extension point can carry the new value end-to-end without touching the core.

An earlier draft of this section argued for strings across all protocol vocabularies on
"open set" grounds, citing extension grant types (`urn:ietf:params:oauth:grant-type:…`),
JARM (`form_post.jwt`), and MTLS auth methods. That was a misapplication of the open-set
argument: of those three, only the MTLS case is genuinely open under the
`IClientSecretHasher` / `IClientSecret` extension model. Extension grant types and JARM
both require framework-side implementation, so a `string` shape only erased compile-time
safety without buying any real extensibility. The corrected distinction is captured above.

**`PromptValue` enum (new — to be created in `src/ZeeKayDa.Auth/PromptValue.cs`).** No
existing enum models the OIDC Core 1.0 §3.1.2.1 `prompt` vocabulary. Specify a new enum,
modelled on the existing `ResponseMode` pattern (`[JsonStringEnumMemberName]` on each member,
`[JsonConverter(typeof(JsonStringEnumConverter<PromptValue>))]` on the type, same namespace
and file-header style), with these members:

| Member | Wire value |
|---|---|
| `None` | `"none"` |
| `Login` | `"login"` |
| `Consent` | `"consent"` |
| `SelectAccount` | `"select_account"` |

The actual `.cs` file is created by the developer during implementation; the ADR fixes the
shape and the members.

**`TokenEndpointAuthMethods` constants class (new — to be created in
`src/ZeeKayDa.Auth/TokenEndpointAuthMethods.cs`).** To eliminate magic strings from consumer
code, the framework ships a public constants class containing the values it recognises:

```csharp
namespace ZeeKayDa.Auth;

/// <summary>
/// Constants for the framework-supported values of
/// <see cref="IClientRegistration.AllowedTokenEndpointAuthMethods"/>. Consumers should
/// reference these constants instead of magic strings. Third parties may introduce
/// additional methods via a custom <see cref="IClientSecretHasher"/> (paired with a
/// custom <see cref="IClientSecret"/> sub-interface); those are represented by their
/// literal protocol string and are not listed here.
/// </summary>
public static class TokenEndpointAuthMethods
{
    public const string ClientSecretBasic = "client_secret_basic";
    public const string ClientSecretPost  = "client_secret_post";
    public const string None              = "none";
    // Future framework-implemented methods (e.g. private_key_jwt, tls_client_auth) will be
    // added here.
}
```

The existing `TokenEndpointAuthMethod` *enum* at `src/ZeeKayDa.Auth/TokenEndpointAuthMethod.cs`
is intentionally **not** repurposed for per-client configuration: it represents the closed set
of methods *this server* implements (for discovery-metadata advertisement), not the open
per-client allowlist. The two types remain separate — see the §1 doc remark on
`AllowedTokenEndpointAuthMethods` so a future reader does not unify them.

**Binding forward constraint on the request-time pipeline.** The request-time validator
operates directly on the enum-typed sets for grant type, response type, response mode, and
prompt — there is no string mapping step, and "unknown value" cannot arise from a well-typed
caller (the only way to inject an undefined enum value is a deliberate
`(GrantType)999`-style cast, defended against by the registration-time `Enum.IsDefined`
check below). For `AllowedTokenEndpointAuthMethods`, the validator MUST reject any presented
method not in the client's configured set with `invalid_client`. Two registration-time
safeguards apply:

1. **Per-value advisory warning.** When an `AllowedTokenEndpointAuthMethods` value matches
   none of the framework-recognised constants on `TokenEndpointAuthMethods`,
   `InMemoryClientRepository` emits an `ILogger.LogWarning` for that value. This is
   informational, not a configuration error, because a custom `IClientSecretHasher` may
   legitimately introduce a new method.
2. **Whole-set startup rejection (unchanged from prior pass).** If the framework recognises
   **none** of the configured methods for a client — i.e. no framework-known constant and
   no custom hasher covers any of them — the client MUST be rejected at startup with
   `ZeeKayDaConfigurationException`. There must be no silent fall-through to "no
   authentication".

For the four enum-typed vocabularies, `InMemoryClientRepository.ValidateClient` additionally
applies an `Enum.IsDefined`-based belt-and-suspenders check at registration time, rejecting
any value not defined on the enum (catches `(GrantType)999`-style casts that bypass the
type system) with `ZeeKayDaConfigurationException`.

### 2. `ClientRegistration` — the default concrete implementation

A `sealed record` is provided in `ZeeKayDa.Auth` as the concrete implementation for consumers
who do not have their own client entity type:

```csharp
namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// An immutable, concrete implementation of <see cref="IClientRegistration"/> for use
/// with <see cref="InMemoryClientRepository"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="ClientId"/> and <see cref="RedirectUris"/> are required (<c>required</c>
/// init-only properties). All other properties have safe defaults.
/// </para>
/// <para>
/// Validation is enforced by <see cref="InMemoryClientRepository"/> at registration time,
/// not in the record constructor, to keep the record itself a pure value object.
/// </para>
/// </remarks>
public sealed record ClientRegistration : IClientRegistration
{
    /// <inheritdoc />
    public required string ClientId { get; init; }

    /// <inheritdoc />
    /// <remarks>
    /// Defaults to <see langword="null"/> (public client). To create a confidential client,
    /// either use <see cref="CreateConfidential"/> (which calls
    /// <see cref="IClientSecretHasher.Create"/> on a supplied hasher) or assign an
    /// <see cref="IClientSecret"/> directly via the record initializer.
    /// </remarks>
    public IClientSecret? ClientSecret { get; init; }

    /// <inheritdoc />
    /// <remarks>
    /// <c>required</c>: the public-vs-confidential distinction is consequential and must be
    /// declared explicitly rather than defaulted. Use <see cref="CreatePublic"/> /
    /// <see cref="CreateConfidential"/> to set this correctly without having to think about
    /// it. The §6 consistency check enforces
    /// <see cref="IsPublic"/> ⇔ <see cref="ClientSecret"/> <c>is null</c> ⇔
    /// <see cref="AllowedTokenEndpointAuthMethods"/> <c>== { None }</c>.
    /// </remarks>
    public required bool IsPublic { get; init; }

    /// <inheritdoc />
    public required IReadOnlySet<string> RedirectUris { get; init; }

    /// <inheritdoc />
    /// <remarks>
    /// <c>required</c>: an empty post-logout-redirect-URI set is a meaningful security
    /// choice (the client cannot use the end-session endpoint with a
    /// <c>post_logout_redirect_uri</c>) and must therefore be declared explicitly. For
    /// clients with no post-logout redirect URIs, pass
    /// <c>new HashSet&lt;string&gt;(StringComparer.Ordinal)</c> (or the collection-expression
    /// form <c>[]</c> target-typed to <see cref="IReadOnlySet{T}"/>).
    /// </remarks>
    public required IReadOnlySet<string> PostLogoutRedirectUris { get; init; }

    /// <inheritdoc />
    public IReadOnlySet<string> AllowedScopes { get; init; }
        = new HashSet<string>(StringComparer.Ordinal);

    /// <inheritdoc />
    public IReadOnlySet<GrantType> AllowedGrantTypes { get; init; }
        = new HashSet<GrantType> { GrantType.AuthorizationCode };

    /// <inheritdoc />
    public IReadOnlySet<ResponseType> AllowedResponseTypes { get; init; }
        = new HashSet<ResponseType> { ResponseType.Code };

    /// <inheritdoc />
    public IReadOnlySet<ResponseMode> AllowedResponseModes { get; init; }
        = new HashSet<ResponseMode> { ResponseMode.Query, ResponseMode.FormPost };

    /// <inheritdoc />
    /// <remarks>
    /// Defaults to <c>{ <see cref="TokenEndpointAuthMethods.ClientSecretBasic"/> }</c>;
    /// for a public client (<see cref="ClientSecret"/> is <see langword="null"/>) construct
    /// the record with <c>AllowedTokenEndpointAuthMethods = { TokenEndpointAuthMethods.None }</c>.
    /// The <see cref="CreateConfidential"/> and <see cref="CreatePublic"/> factory methods
    /// apply the appropriate default automatically. Reference
    /// <see cref="TokenEndpointAuthMethods"/> constants instead of raw string literals.
    /// </remarks>
    public IReadOnlySet<string> AllowedTokenEndpointAuthMethods { get; init; }
        = new HashSet<string>(StringComparer.Ordinal)
            { TokenEndpointAuthMethods.ClientSecretBasic };

    /// <inheritdoc />
    public IReadOnlySet<PromptValue> AllowedPromptValues { get; init; }
        = new HashSet<PromptValue>
            {
                PromptValue.Login, PromptValue.None,
                PromptValue.Consent, PromptValue.SelectAccount,
            };

    /// <inheritdoc />
    public bool EnableZkdErrorCodes { get; init; }

    /// <inheritdoc />
    /// <remarks>
    /// Not <c>required</c>: defaults to <see langword="null"/>, meaning "inherit
    /// <c>IdTokenOptions.SigningAlgValuesSupported</c>". When non-null, must be a non-empty
    /// subset of the globally configured set (validated at registration time and at host
    /// startup — see §6 and §8).
    /// </remarks>
    public IReadOnlySet<SigningAlgorithm>? AllowedSigningAlgorithms { get; init; }
}
```

`ClientRegistration` is a `record` rather than a `class` because:
- Records provide structural equality out of the box, which simplifies tests.
- `with`-expression copying is idiomatic for constructing slightly modified test variants.
- The `required` + `init`-only pattern gives compile-time enforcement of mandatory fields without
  a proliferation of constructor overloads.

**Why keep validation out of the record constructor?**
Putting URI scheme checks and fragment-detection logic in the record constructor would mean the
constructor throws for invalid input, which conflicts with the test-value-construction use case
(a test may intentionally construct a `ClientRegistration` with a bad URI to test the
validator, not the record itself). Validation lives in `InMemoryClientRepository` (see §6) and in
the request-time validation pipeline.

### 3. Client secret model and the composite hasher

The framework cleanly separates **what is stored** (data — `IClientSecret`) from **how to
verify and create it** (behaviour — `IClientSecretHasher`). Earlier drafts conflated the two
on `IClientRegistration` itself by exposing an `IClientSecretVerifier? SecretVerifier`
property; that was hostile to ORM-mapped implementations (an EF entity does not naturally
carry a service reference) and forced consumers who wanted a database-backed
`IClientRepository` to bridge a behavioural service onto each row at materialisation time.
Both problems are eliminated by the model below:

- **`IClientSecret`** — pure-data marker hierarchy. The C# type identity *is* the algorithm
  identifier — no `Algorithm` discriminator string. ORM mappings store flat columns and
  project to a sub-interface in a `[NotMapped]` adapter (or equivalent for NHibernate /
  Dapper).
- **`IClientSecretHasher`** — behavioural service that knows how to verify and create a
  particular family of `IClientSecret`s. Resolved from DI as a singleton.
- **`CompositeClientSecretHasher`** — framework-internal coordinator that fans out across
  every registered hasher.

#### 3.1 `IClientSecret` — pure data marker hierarchy

```csharp
namespace ZeeKayDa.Auth;

/// <summary>
/// Marker interface representing the stored credential for a confidential client. Implementations
/// are pure data carriers — no behaviour. Verification and creation are delegated to
/// <see cref="IClientSecretHasher"/> implementations.
/// </summary>
/// <remarks>
/// Algorithm-specific properties live on derived interfaces (<see cref="IPbkdf2ClientSecret"/>,
/// custom-implemented bcrypt/argon2 sub-interfaces, …). The base type is empty so that ORM-mapped
/// implementations are unconstrained — a consumer's EF entity can map flat columns
/// (algorithm name, iterations, salt, hash, plus any algorithm-specific extras) and expose them
/// via the appropriate sub-interface.
/// </remarks>
public interface IClientSecret;

/// <summary>
/// A PBKDF2-hashed client secret. Stores iteration count, salt, and hash. The framework's default
/// <see cref="IClientSecretHasher"/> (<see cref="Pbkdf2ClientSecretHasher"/>) operates on this
/// shape. Consumers using EF Core can map all four properties as primitives.
/// </summary>
public interface IPbkdf2ClientSecret : IClientSecret
{
    int Iterations { get; }
    byte[] Salt { get; }
    byte[] Hash { get; }
}

/// <summary>
/// Default record implementation of <see cref="IPbkdf2ClientSecret"/>. Consumers may use this
/// directly or implement their own type (typically an EF entity).
/// </summary>
public sealed record Pbkdf2ClientSecret(
    int Iterations,
    byte[] Salt,
    byte[] Hash) : IPbkdf2ClientSecret;
```

There is deliberately no `string Algorithm` property on `IClientSecret` — the C# type
identity *is* the algorithm. A consumer adding bcrypt defines
`IBCryptClientSecret : IClientSecret` with whatever fields bcrypt needs (cost factor, encoded
hash) and a paired `BCryptClientSecretHasher : ClientSecretHasher<IBCryptClientSecret>`.

#### 3.2 `IClientSecretHasher` — single contract for create + verify

```csharp
namespace ZeeKayDa.Auth;

/// <summary>
/// Combined factory and verifier for a particular family of <see cref="IClientSecret"/>
/// implementations. Each registered hasher declares which secrets it can handle; the framework's
/// internal composite hasher dispatches verification by querying each registered hasher in turn.
/// </summary>
/// <remarks>
/// Most consumers should inherit from <see cref="ClientSecretHasher{TSecret}"/> rather than
/// implement this interface directly — the generic base provides the standard "I handle a single
/// sub-interface" dispatch logic.
///
/// Implementations MUST:
/// <list type="bullet">
///   <item>Use a fixed-time comparison (<see cref="System.Security.Cryptography.CryptographicOperations.FixedTimeEquals"/>) inside <see cref="Verify"/>.</item>
///   <item>NOT throw from any method. Internal errors MUST be caught and surfaced as <c>Verify == false</c> (or as a <see cref="ZeeKayDaConfigurationException"/> at construction time for invalid configuration only).</item>
///   <item>NOT log, expose in exception messages, or include in telemetry the presented secret value or any derivative.</item>
///   <item>Be safe to call concurrently — hashers are resolved as singletons.</item>
/// </list>
/// </remarks>
public interface IClientSecretHasher
{
    /// <summary>
    /// Returns <see langword="true"/> if this hasher recognises the given secret type and can
    /// verify a presented plaintext against it. Typically implemented as <c>secret is TSecret</c>.
    /// </summary>
    bool CanHandle(IClientSecret secret);

    /// <summary>
    /// Verifies a presented plaintext against the stored secret. Callers MUST check
    /// <see cref="CanHandle"/> first; calling <see cref="Verify"/> with an incompatible
    /// <paramref name="stored"/> returns <see langword="false"/>.
    /// </summary>
    bool Verify(IClientSecret stored, ReadOnlySpan<char> presented);

    /// <summary>
    /// Creates a new <see cref="IClientSecret"/> from a plaintext secret. The returned instance's
    /// concrete type is what this hasher produces (e.g. <see cref="Pbkdf2ClientSecret"/>).
    /// </summary>
    IClientSecret Create(string plaintext);
}

/// <summary>
/// Generic base class for the typical "I handle a single <typeparamref name="TSecret"/> shape"
/// hasher. Eliminates boilerplate.
/// </summary>
public abstract class ClientSecretHasher<TSecret> : IClientSecretHasher
    where TSecret : IClientSecret
{
    public bool CanHandle(IClientSecret secret) => secret is TSecret;

    public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented) =>
        stored is TSecret typed && VerifyCore(typed, presented);

    public IClientSecret Create(string plaintext) => CreateCore(plaintext);

    protected abstract bool VerifyCore(TSecret stored, ReadOnlySpan<char> presented);
    protected abstract TSecret CreateCore(string plaintext);
}
```

#### 3.3 `Pbkdf2ClientSecretHasher` — framework default

```csharp
public sealed class Pbkdf2ClientSecretHasher : ClientSecretHasher<IPbkdf2ClientSecret>
{
    public const int DefaultIterations = 600_000;
    public const int MinimumIterations = 100_000;
    public const int SaltSize = 16;
    public const int HashSize = 32;

    private readonly int _iterations;

    public Pbkdf2ClientSecretHasher() : this(DefaultIterations) { }

    public Pbkdf2ClientSecretHasher(int iterations)
    {
        if (iterations < MinimumIterations)
            throw new ZeeKayDaConfigurationException(
                $"PBKDF2 iterations must be >= {MinimumIterations}; got {iterations}.");
        _iterations = iterations;
    }

    protected override bool VerifyCore(IPbkdf2ClientSecret stored, ReadOnlySpan<char> presented)
    {
        // Defence-in-depth: an empty presented secret is never valid. Rfc2898DeriveBytes
        // does not reject empty input on its own; rejecting here means the per-hasher
        // empty-string defence in §6 holds for PBKDF2 even if the stored hash were
        // (somehow) the PBKDF2 derivation of "". See §8 validation table.
        if (presented.IsEmpty) return false;
        if (stored.Iterations < MinimumIterations) return false;
        if (stored.Salt.Length < SaltSize) return false;
        if (stored.Hash.Length != HashSize) return false;
        var computed = Rfc2898DeriveBytes.Pbkdf2(
            presented, stored.Salt, stored.Iterations, HashAlgorithmName.SHA256, HashSize);
        return CryptographicOperations.FixedTimeEquals(computed, stored.Hash);
    }

    protected override IPbkdf2ClientSecret CreateCore(string plaintext)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(plaintext, salt, _iterations, HashAlgorithmName.SHA256, HashSize);
        return new Pbkdf2ClientSecret(_iterations, salt, hash);
    }

    public override string ToString() =>
        $"Pbkdf2ClientSecretHasher {{ Iterations = {_iterations} }}";
}
```

Concrete parameter table:

| Parameter | Value |
|---|---|
| Algorithm | PBKDF2-HMAC-SHA256 |
| Iteration count (default) | **600,000** (current OWASP guidance for PBKDF2-SHA256) |
| Iteration count (minimum) | **100,000** — values below this throw `ZeeKayDaConfigurationException` at construction |
| Salt length | **16 bytes** (`RandomNumberGenerator.GetBytes(16)` on `Create`) |
| Hash length | **32 bytes** (HMAC-SHA256 output, no truncation) |

`ToString()` deliberately does not expose any salt/hash material — only the iteration count.
`IPbkdf2ClientSecret` instances themselves never appear in framework log output.

#### 3.4 `CompositeClientSecretHasher` — framework-internal coordinator

```csharp
internal sealed class CompositeClientSecretHasher : IClientSecretHasher
{
    private readonly IReadOnlyList<IClientSecretHasher> _hashers;
    private readonly IClientSecretHasher _default;
    private readonly IClientSecret _dummySecret;
    private readonly string _dummyPresented;

    public CompositeClientSecretHasher(
        IEnumerable<IClientSecretHasher> hashers,
        IOptions<ClientSecretHasherOptions> options)
    {
        _hashers = hashers.ToArray();
        if (_hashers.Count == 0)
            throw new ZeeKayDaConfigurationException(
                "No IClientSecretHasher registered. Call AddSecretsHasher<T>() at minimum.");

        _default = ResolveDefault(_hashers, options.Value);
        _dummySecret = _default.Create("__zkd_unknown_client_padding__");
        _dummyPresented = "__zkd_unknown_client_padding__";
    }

    public bool CanHandle(IClientSecret secret) =>
        _hashers.Any(h => h.CanHandle(secret));

    /// <summary>
    /// First-match-wins dispatch. If no registered hasher recognises the secret, the call returns
    /// <see langword="false"/> after invoking the default hasher with a dummy secret to keep the
    /// failure path's wall-clock time comparable to the success path (see §3b timing padding).
    /// </summary>
    public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented)
    {
        foreach (var h in _hashers)
        {
            if (h.CanHandle(stored))
            {
                var result = h.Verify(stored, presented);
                if (!result) PadTiming();
                return result;
            }
        }
        PadTiming();
        return false;
    }

    public IClientSecret Create(string plaintext) => _default.Create(plaintext);

    private void PadTiming()
    {
        // Fixed-time dummy verify against the default hasher to dominate the response time
        // with the default's work factor. See §3b "Timing padding for fast hashers".
        _ = _default.Verify(_dummySecret, _dummyPresented);
    }

    private static IClientSecretHasher ResolveDefault(
        IReadOnlyList<IClientSecretHasher> hashers,
        ClientSecretHasherOptions options) { /* …per resolution table in §3.6… */ }
}
```

`Verify` is also called by the framework's "unknown client" path (see §3b) — when
`IClientRepository.FindByClientIdAsync` returns `null`, the token endpoint still calls
`CompositeClientSecretHasher.Verify(_dummySecret, presentedSecret)` to keep timing uniform.

**Why `CompositeClientSecretHasher` is registered as the concrete type, NOT as
`IClientSecretHasher`.** If the composite were registered as `IClientSecretHasher`, the
`IEnumerable<IClientSecretHasher>` injected into its own constructor would include
*itself* — infinite recursion on first `Verify`. Framework code that needs to verify or
create takes a dependency on the concrete `CompositeClientSecretHasher` type. Consumers
must NOT register `CompositeClientSecretHasher` as `IClientSecretHasher`; this is documented
as a hard rule on the type's XML doc.

#### 3.5 DI registration — `AddSecretsHasher<T>(isDefault)` extension

```csharp
public sealed class ClientSecretHasherOptions
{
    /// <summary>
    /// Hasher types that have been registered with <c>isDefault: true</c>. Validated at startup:
    /// 0 explicit defaults + 1 hasher → that hasher is the default; 0 + 2+ → throws; 1 → that
    /// type is the default; 2+ → throws.
    /// </summary>
    internal List<Type> ExplicitDefaults { get; } = new();
}

public static ZeeKayDaAuthBuilder AddSecretsHasher<THasher>(
    this ZeeKayDaAuthBuilder builder,
    bool isDefault = false)
    where THasher : class, IClientSecretHasher
{
    builder.Services.TryAddEnumerable(
        ServiceDescriptor.Singleton<IClientSecretHasher, THasher>());

    if (isDefault)
        builder.Services.Configure<ClientSecretHasherOptions>(
            o => o.ExplicitDefaults.Add(typeof(THasher)));

    return builder;
}
```

Inside `AddZeeKayDaAuth(...)` (at the framework registration layer), the framework registers
`Pbkdf2ClientSecretHasher` automatically — without `isDefault: true`:

```csharp
services.AddSingleton<CompositeClientSecretHasher>();
services.TryAddEnumerable(
    ServiceDescriptor.Singleton<IClientSecretHasher, Pbkdf2ClientSecretHasher>());
services.AddOptions<ClientSecretHasherOptions>();
services.AddSingleton<IValidateOptions<ClientSecretHasherOptions>,
                     ClientSecretHasherOptionsValidator>();
services.AddOptions<ClientSecretHasherOptions>().ValidateOnStart();
```

The `TryAddEnumerable` semantics mean that a consumer who calls
`AddSecretsHasher<Pbkdf2ClientSecretHasher>(isDefault: true)` to make their tuned-iteration
hasher *the* default does not produce a duplicate registration of the type — the
explicit-default flag is recorded in `ClientSecretHasherOptions` and the validator picks
it up.

#### 3.6 Startup resolution rules

`ClientSecretHasherOptionsValidator : IValidateOptions<ClientSecretHasherOptions>` enforces
the agreed table:

| # registered `IClientSecretHasher` | # in `ExplicitDefaults` | Outcome |
|---|---|---|
| 1 | 0 or 1 | That hasher is the default |
| 2+ | 1 | The flagged type is the default |
| 2+ | 0 | **`ZeeKayDaConfigurationException`** at startup with a message naming the registered hashers and explaining `AddSecretsHasher<T>(isDefault: true)` |
| 2+ | 2+ | **`ZeeKayDaConfigurationException`** at startup naming the conflicting types |
| 0 | (any) | **`ZeeKayDaConfigurationException`** at startup |

The validator enumerates `IClientSecretHasher` registrations from the `IServiceProvider`
(matching the same pattern §6 below uses for the missing-`IClientRepository` startup check).
All four exception types are `ZeeKayDaConfigurationException` per ADR 0006 §1.

Required exception messages — exact wording fixed by this ADR:

- **0 hashers registered**:
  `"No IClientSecretHasher has been registered. Call AddSecretsHasher<T>() at least once, or rely on the framework's default Pbkdf2ClientSecretHasher (registered automatically by AddZeeKayDaAuth)."`
- **2+ hashers, 0 explicit defaults**:
  `"Multiple IClientSecretHasher implementations are registered ({TypeNames}) but none has been declared the default. Call AddSecretsHasher<T>(isDefault: true) on exactly one of them so the framework knows which hasher to use when creating new client secrets."`
  where `{TypeNames}` is a comma-separated list of the registered types' full names, e.g.
  `"ZeeKayDa.Auth.Pbkdf2ClientSecretHasher, Contoso.Auth.BCryptClientSecretHasher"`.
- **2+ explicit defaults**:
  `"Multiple IClientSecretHasher implementations have been declared the default ({TypeNames}). Exactly one hasher must be the default. Remove the isDefault: true flag from all but one AddSecretsHasher<T>() registration."`

#### 3.7 ORM friendliness

The data-vs-behaviour split makes this design especially friendly to ORM-mapped
`IClientRepository` implementations:

- An EF Core entity stores `Pbkdf2Iterations`, `Pbkdf2Salt`, `Pbkdf2Hash` as flat primitive
  columns and exposes `IClientSecret? ClientSecret` via a `[NotMapped]` projection.
- NHibernate uses a component mapping; Dapper uses a hand-written projection in the
  query.
- No polymorphic property mapping, owned-type acrobatics, or TPH discriminators are
  required.
- No service references travel on the entity.

A worked EF entity sketch is shown in §7.

#### 3.8 Public vs confidential client distinction

The `IsPublic` property (declared on `IClientRegistration`) is the authoritative indicator of
client confidentiality. `ClientSecret` and `AllowedTokenEndpointAuthMethods` must agree with
it; the §6 consistency check fails startup with `ZeeKayDaConfigurationException` on
violation.

| `IsPublic` | `ClientSecret` | `AllowedTokenEndpointAuthMethods` | Meaning |
|---|---|---|---|
| `true`  | `null`     | exactly `{ TokenEndpointAuthMethods.None }` | Public client (SPA, native app, device) |
| `false` | non-`null` | MUST NOT contain `TokenEndpointAuthMethods.None` | Confidential client |

**Binding rules on the framework** — forward constraints for the future
token-endpoint and authorization-endpoint ADRs:

1. Token endpoint client authentication MUST delegate to
   `CompositeClientSecretHasher.Verify(client.ClientSecret!, presented)` for confidential
   clients. The framework MUST NOT compare strings itself.
2. `IsPublic == true` (equivalently, `ClientSecret is null`) means "public client" — any
   presented `client_secret` MUST cause the request to be rejected with `invalid_client`.
3. To keep timing uniform between "unknown client" and "wrong secret", the framework MUST
   call `CompositeClientSecretHasher.Verify(_dummySecret, presented)` on the unknown-client
   path. The composite's internal dummy is constructed from the resolved default hasher at
   startup (see §3.4); its work factor matches the default's success path.
4. `InMemoryClientRepository` validates `client.ClientSecret` against the empty string at
   construction time (using the resolved composite hasher) — defence-in-depth against a
   custom hasher that accepts empty input through a comparison bug. See §6.

**Validation rules by client type:**

| Rule | Public | Confidential |
|---|---|---|
| PKCE (`code_challenge` + `code_challenge_method`) required | ✅ Always enforced | ✅ Always enforced (OAuth 2.1 §7.6) |
| `client_secret` in token request | Not expected; treated as an error if present | Required |
| `client_id` in token request | Required | Required |

**No separate types for public and confidential clients.** Splitting into two types
(`PublicClientRegistration` and `ConfidentialClientRegistration`) was considered (see Rejected
Alternatives). A single interface with a declared `IsPublic` property was chosen because:
(a) the framework's internal validation logic branches on `IsPublic` — a single type means
a single return type from `IClientRepository`, no discriminated unions; (b) the distinction is a
single boolean; the type-system overhead of two separate types is not justified by the
complexity it would encode.

### 3b. Client enumeration mitigation — forward constraints

The following constraints are binding on the future authorization-endpoint and token-endpoint
ADRs to prevent an attacker from probing the AS to enumerate valid `client_id`s:

- **Token endpoint:** `invalid_client` is returned uniformly for both "unknown `client_id`" and
  "wrong `client_secret`". The `error_description` MUST NOT include the `client_id` or any
  string derived from it. Per §3.8 rule 3, the framework calls
  `CompositeClientSecretHasher.Verify(_dummySecret, presented)` whenever the `client_id`
  lookup returns `null` so that the wall-clock time is indistinguishable from a real
  wrong-secret failure.
- **Authorization endpoint:** an unknown `client_id` MUST fail *before* any redirect is
  performed, rendering a generic error page that does NOT echo the supplied `client_id` into the
  HTML body (mitigating both enumeration via timing and reflective XSS via unencoded echoing).
  If the `client_id` ever needs to appear in operator-facing logs or error pages, it MUST be
  HTML-encoded.

**Timing padding for fast hashers** *(binding forward constraint on the token-endpoint ADR).*
The dummy-hasher defence in the bullet above only equalises timing when the matched client's
hasher is itself comparable in cost to the default hasher. Where the matched client's hasher
completes faster than the default — typical for any future hardware-backed or remote-KMS hasher,
or a consumer-introduced fast verifier — the framework MUST also pad the **known-client failure
path** so the observable wall-clock time on every `invalid_client` outcome is dominated by the
default hasher's work factor. This is implemented inside `CompositeClientSecretHasher.Verify`:
on every `false` outcome (whether from the matched-hasher path or the no-hasher-recognises-this-
secret fall-through), the composite invokes `CompositeClientSecretHasher.PadTiming()`, which
calls `_default.Verify(_dummySecret, _dummyPresented)` against a precomputed dummy secret with
a fixed dummy presented-plaintext (both constructed at composite startup from the resolved
default hasher; see §3.4). The principle is unchanged from the prior pass — every
`invalid_client` failure path performs work comparable to the default hasher's success path —
so a third-party fast custom hasher cannot reopen the enumeration oracle.

**Rate limiting.** Rate limiting on the token and authorization endpoints is the operator's
responsibility; the framework will expose hooks (deferred to a future rate-limiting ADR) but
does not implement throttling itself. The timing-uniformity constraints above are necessary but
not sufficient to defeat a sustained enumeration attempt — operators MUST also rate-limit
unauthenticated endpoints at their edge.

### 4. Redirect URI validation rules

Per RFC 6749 §3.1.2, RFC 9700 §2.1, and RFC 8252 §7.3:

**Rule 1 — Exact-string comparison at request time (with one exception).**  
The `redirect_uri` in an authorization request must be an exact string match of one of the
client's registered `RedirectUris`. No normalization (e.g., adding a trailing slash), no prefix
matching, no wildcard patterns. This is the single most effective control against open-redirect
abuse via redirect URI manipulation.

**Exception — RFC 8252 §7.3 loopback port.** When a registered redirect URI is HTTP on a loopback
host (per the loopback test below), the request-time match compares scheme, host, path, query,
and userinfo for exact equality but **ignores the port component**. Registered URIs may specify
any port (or be registered with a placeholder such as port 0); at request time the AS accepts any
port from the same loopback host. This exception applies ONLY at request-time matching; the
registered URI is stored as-is.

**Rule 2 — No fragment component in registered URIs.**  
A fragment component (`#`) in a registered redirect URI is prohibited. RFC 6749 §3.1.2 states that
"the endpoint URI MUST NOT include a fragment component". This is enforced at registration time
by `InMemoryClientRepository` — a URI whose parsed `Uri.Fragment` is non-empty is rejected with
an `ArgumentException` before the server ever starts accepting requests. For custom
`IClientRepository` implementations, the framework performs the same fragment check at request
time as a belt-and-suspenders measure.

**Rule 3 — Scheme allowlist.**  
A redirect URI is acceptable only if its scheme matches one of:

- **`https`** — any host (subject to other rules).
- **`http`** — loopback host only (per RFC 8252 §7.3 and the loopback test below).
- **A private-use URI scheme** per RFC 8252 §7.1, defined narrowly as:
  the scheme **contains at least one `.`** (e.g. `com.example.app`) **AND** is **not** one of
  the explicitly forbidden web/script/data schemes:
  `http`, `https` (already handled above and excluded from this branch),
  `javascript`, `data`, `file`, `vbscript`, `about`, `blob`, `ws`, `wss`, `ftp`,
  `mailto`, `tel`.

The `.`-in-scheme check is a **structural proxy** for the RFC 8252 §7.1 requirement that the
scheme be "a domain name under the app developer's control, in reverse-DNS notation". The
framework cannot verify domain ownership; operators are responsible for not picking someone
else's reverse-DNS scheme (a malicious app registered with `com.competitor.app` on the same
device could otherwise intercept callbacks). The `.` check rules out the most common
non-reverse-DNS shapes (e.g. `myapp`, `intent`) but is not a substitute for operator diligence.

Any other scheme is rejected at registration time. The allowlist-with-narrow-private-use
construction is deliberate: a pure denylist fails open on future browser-introduced schemes (e.g.
hypothetical `intent:`, `chrome-extension:`, …) that an attacker could later abuse.

**Same rules apply to `PostLogoutRedirectUris`.** Rules 1–5 above are applied identically to
the `PostLogoutRedirectUris` set: scheme allowlist, no fragment, no userinfo, no `.`/`..` path
segments, and the same loopback-port exception at request-time match against the OIDC
RP-Initiated Logout 1.0 `post_logout_redirect_uri` parameter. `InMemoryClientRepository`
implements both validations via a shared helper — see §6.

**Rule 4 — No userinfo component.**  
URIs whose `Uri.UserInfo` is non-empty (e.g. `https://user:pass@host/cb`) are rejected at
registration time. Userinfo in redirect URIs is a well-known phishing/spoofing primitive and has
no legitimate use for an OAuth callback.

**Rule 5 — Loopback host test.**  
The loopback test is used by both Rule 1 (port exception) and Rule 3 (HTTP allowance):

```csharp
static bool IsLoopback(Uri uri)
{
    if (string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase))
        return true;
    return IPAddress.TryParse(uri.Host, out var ip) && IPAddress.IsLoopback(ip);
}
```

`IPAddress.IsLoopback` correctly covers `127.0.0.0/8`, `::1`, and any canonical IPv6 form
(`[::1]`, `[0:0:0:0:0:0:0:1]`, IPv4-mapped variants, …) without us having to enumerate them by
string. `Uri.Host` strips the brackets from bracketed IPv6 literals so `IPAddress.TryParse`
parses cleanly. The earlier draft's string comparison against `"[::1]"` was a bug — `Uri.Host`
never contains brackets — and is replaced by this single helper everywhere.

**`localhost` vs IP literal.** `localhost` is allowed for ergonomics, but at registration time
the framework emits an `ILogger.LogWarning` recommending the IP literal per RFC 8252 §8.3
(DNS rebinding considerations). The check uses `string.Equals("localhost", host, OrdinalIgnoreCase)`
— a whole-string equality, never substring — so `localhost.attacker.com` is correctly rejected
because it falls through to the standard non-loopback HTTPS-only rule.

Enforced at registration time in `InMemoryClientRepository`:

```csharp
// Redirect URI validation sketch (inside InMemoryClientRepository)
private static readonly HashSet<string> _forbiddenPrivateUseSchemes =
    new(StringComparer.OrdinalIgnoreCase)
    {
        "http", "https", "javascript", "data", "file", "vbscript",
        "about", "blob", "ws", "wss", "ftp", "mailto", "tel",
    };

private static void ValidateRedirectUri(string raw, string clientId, ILogger logger)
{
    if (string.IsNullOrWhiteSpace(raw))
        throw new ArgumentException(
            $"Client '{clientId}': a redirect URI must not be null, empty, or whitespace.");

    if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri))
        throw new ArgumentException(
            $"Client '{clientId}': redirect URI '{raw}' is not a valid absolute URI.");

    // Rule 2 — no fragment
    if (!string.IsNullOrEmpty(uri.Fragment))
        throw new ArgumentException(
            $"Client '{clientId}': redirect URI '{raw}' must not contain a fragment " +
            "component (RFC 6749 §3.1.2).");

    // Rule 4 — no userinfo
    if (!string.IsNullOrEmpty(uri.UserInfo))
        throw new ArgumentException(
            $"Client '{clientId}': redirect URI '{raw}' must not contain a userinfo component.");

    // Defence — reject `.` / `..` path segments (ambiguous canonicalisation).
    // Backs the `https://x/cb/../cb` edge-case matrix row.
    foreach (var segment in uri.Segments)
    {
        var trimmed = segment.TrimEnd('/');
        if (trimmed == "." || trimmed == "..")
            throw new ArgumentException(
                $"Client '{clientId}': redirect URI '{raw}' contains a '.' or '..' path " +
                "segment, which is ambiguous under URI canonicalisation. Resolve to the " +
                "canonical form before registering.");
    }

    var scheme = uri.Scheme;

    if (string.Equals(scheme, "https", StringComparison.OrdinalIgnoreCase))
    {
        // HTTPS — accepted unconditionally.
        return;
    }

    if (string.Equals(scheme, "http", StringComparison.OrdinalIgnoreCase))
    {
        // Rule 3 (http branch) — loopback only.
        if (!IsLoopback(uri))
            throw new ArgumentException(
                $"Client '{clientId}': redirect URI '{raw}' uses HTTP on a non-loopback " +
                "host. Non-loopback redirect URIs must use HTTPS (RFC 9700 §2.1).");

        // S-S2 — recommend IP literal over "localhost".
        if (string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            logger.LogWarning(
                "Client '{ClientId}': redirect URI '{Uri}' uses 'localhost'. Prefer the " +
                "loopback IP literal (127.0.0.1 or [::1]) per RFC 8252 §8.3.",
                clientId, raw);
        }
        return;
    }

    // Rule 3 (private-use branch).
    if (_forbiddenPrivateUseSchemes.Contains(scheme) || !scheme.Contains('.'))
        throw new ArgumentException(
            $"Client '{clientId}': redirect URI '{raw}' uses scheme '{scheme}', which is not " +
            "an allowed redirect URI scheme. Allowed: 'https', 'http' (loopback only), or a " +
            "reverse-DNS private-use scheme per RFC 8252 §7.1 (e.g. 'com.example.app').");
}
```

**Where validation runs — belt-and-suspenders:**

| Validation point | Covers | Fails with |
|---|---|---|
| `InMemoryClientRepository` constructor | Clients registered via `AddInMemoryClients` | `ArgumentException` (startup) |
| Startup options validation (see §6) | A missing/unconfigured `IClientRepository` | `ZeeKayDaConfigurationException` (startup) |
| Request-time pipeline | All clients (including custom repository results) | OAuth `invalid_request` error response |

The registration-time check catches configuration mistakes immediately (the server won't start with
a bad URI). The request-time check is the authoritative security control, because a custom
`IClientRepository` implementation may not have its own validation. Consumers providing a custom
repository must ensure their registrations are equally well-validated; this ADR documents what
rules the framework expects to be upheld.

**`Uri` parsing, not string manipulation.** All URI analysis uses `Uri.TryCreate` and structured
`Uri` properties (`Scheme`, `Host`, `Fragment`, `UserInfo`, `Port`). String operations on raw URI
values (e.g. `Contains("#")`) are explicitly prohibited in the implementation — they produce
incorrect results for encoded fragments and URL-encoded characters.

**Locked-down URI edge cases.** The following cases describe behaviour the implementation MUST
satisfy. They are not a test plan — they are the behavioural contract:

| Input (registered or requested) | Expected outcome |
|---|---|
| `https://x/cb#` (registration) | **Rejected** — fragment component present (Rule 2) |
| `https://x/cb%23foo` (registration) | **Accepted** — encoded `#` is path data, not a fragment |
| Registered `https://X/cb`, requested `https://x/cb` | **No match** — exact byte-for-byte (case-sensitive) comparison |
| `https://x/cb/../cb` (registration) | **Rejected** — `.`/`..` path-segment check in `ValidateRedirectUri` (ambiguous canonicalisation) |
| `https://user:pass@x/cb` (registration) | **Rejected** — userinfo present (Rule 4) |
| Registered `http://127.0.0.1:53281/cb`, requested `http://127.0.0.1:65000/cb` | **Match** — loopback port exception (Rule 1) |
| `http://example.com/cb` (registration) | **Rejected** — HTTP on non-loopback (Rule 3) |
| `javascript:alert(1)` (registration) | **Rejected** — scheme not in allowlist (Rule 3) |
| `com.example.app:/callback` (registration) | **Accepted** — reverse-DNS private-use scheme |
| `myapp:/callback` (registration) | **Rejected** — no `.` in scheme; not a private-use scheme |
| Registered redirect URI on `localhost` (HTTP) | **Accepted with `LogWarning`** recommending the IP literal |
| `localhost.attacker.com` host | **Rejected** — fails whole-string `localhost` check; falls through to non-loopback HTTPS-only rule |

### 5. Scope intersection rule

`IClientRegistration.AllowedScopes` is the authoritative set of scopes the client is registered
for. The framework applies a two-level intersection when computing the effective granted scope set:

```
effective_scopes = (requested_scopes ∩ client.AllowedScopes) ∩ user_granted_scopes
```

**Step 1 — request validation, before consent.** Scopes requested but not in
`client.AllowedScopes` are **silently dropped** during request validation. If the resulting
effective scope set is empty, the request is rejected with `invalid_scope` per RFC 6749 §4.1.2.1.
The framework does NOT echo back which scopes were dropped (this would leak the client's
permitted-scope set to an attacker controlling the request).

**Step 2 — consent grant (`IConsentInteraction.GrantAsync`).** As established in ADR 0005 §7, the
`grantedScopes` argument is re-intersected with the client's `AllowedScopes` inside `GrantAsync`,
applying exactly the same silent-drop rule. This ensures that a host bug that passes through
requested scopes verbatim — without consulting `AllowedScopes` — cannot grant scopes the client is
not registered for. The framework is the last line of defence regardless of how the host computes
its `grantedScopes` argument.

**Consequence:** `AllowedScopes` is a hard cap. The consent UI may show fewer scopes than the
allowed set (e.g. the user's plan does not include a premium scope), but it can never grant more.
The framework enforces this regardless of what the host passes to `GrantAsync`.

**Ordinal comparison.** Scope name comparison uses `StringComparer.Ordinal` — the same comparer
used for registered scope names in `InMemoryScopeRepository`. Case-sensitive, no normalization.
Scope names that differ only by case are treated as distinct (consistent with the OAuth 2.x
specs, which treat scope strings as case-sensitive identifiers).

### 6. `IClientRepository` abstraction

```csharp
namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Provides client registrations to the authorization server.
/// </summary>
/// <remarks>
/// <para>
/// Implementation contract:
/// </para>
/// <list type="bullet">
///   <item><description>
///     Lookup by <c>client_id</c> MUST be parametrised at the storage layer (no string
///     concatenation into SQL or other query languages); the <c>client_id</c> is
///     attacker-controlled input.
///   </description></item>
///   <item><description>
///     A return of <see langword="null"/> means "no such client". Implementations MUST NOT
///     throw to signal an unknown <c>client_id</c>; throwing would change the wall-clock
///     timing of the unknown-client path and undermine the enumeration defence in §3b.
///   </description></item>
///   <item><description>
///     Implementations MUST NOT throw for a malformed <c>client_id</c> input either —
///     return <see langword="null"/> and let the framework's input validator produce the
///     protocol error. Throwing on malformed input would create a different timing/error
///     signature for "structurally invalid" vs "not found" and undermine §3b.
///   </description></item>
///   <item><description>
///     Returned <see cref="IClientRegistration"/> instances MUST satisfy every rule the
///     framework documents for <see cref="InMemoryClientRepository"/> (§4, §8). The framework
///     applies belt-and-suspenders request-time checks, but a non-conforming registration
///     may still cause the authorization request to fail with <c>invalid_request</c>.
///   </description></item>
/// </list>
/// </remarks>
public interface IClientRepository
{
    /// <summary>
    /// Looks up a client registration by its <c>client_id</c>.
    /// </summary>
    /// <param name="clientId">The <c>client_id</c> from the incoming request.</param>
    /// <param name="cancellationToken">A token that can be used to cancel the operation.</param>
    /// <returns>
    /// The matching <see cref="IClientRegistration"/>, or <see langword="null"/> if no client
    /// with the given <paramref name="clientId"/> is registered.
    /// </returns>
    ValueTask<IClientRegistration?> FindByClientIdAsync(
        string clientId,
        CancellationToken cancellationToken = default);
}
```

The rename from `IClientStore` to `IClientRepository` aligns with the existing project
convention (`IScopeRepository`). `ValueTask<IClientRegistration?>` mirrors the return-type
pattern established by `IScopeRepository`. `InMemoryClientRepository` returns synchronously via
`ValueTask.FromResult(...)`; a database-backed repository wraps its `Task<T>` via
`new ValueTask<IClientRegistration?>(task)`. No boxing occurs in either case on .NET 10.

**`InMemoryClientRepository`** lives in `ZeeKayDa.Auth`, mirroring `InMemoryScopeRepository`:

```csharp
namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// An in-memory <see cref="IClientRepository"/> implementation.
/// </summary>
/// <remarks>
/// All clients are validated at construction time. Startup fails loudly if any
/// client registration violates the rules in §4 or §8.
/// </remarks>
public sealed class InMemoryClientRepository : IClientRepository
{
    private readonly IReadOnlyDictionary<string, IClientRegistration> _clients;

    /// <param name="clients">The client registrations to expose from this repository.</param>
    /// <param name="compositeHasher">
    /// The framework-internal composite hasher, used at construction time for the
    /// per-client empty-string defence-in-depth check (§3.8 rule 4 / §6).
    /// </param>
    /// <param name="logger">A logger used for non-fatal advisory warnings (e.g. localhost use).</param>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="clients"/>, <paramref name="compositeHasher"/>, or
    /// <paramref name="logger"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when any client registration violates validation rules (duplicate
    /// <c>client_id</c>, missing redirect URIs, fragment in URI, HTTP on non-loopback, etc.).
    /// </exception>
    public InMemoryClientRepository(
        IEnumerable<IClientRegistration> clients,
        CompositeClientSecretHasher compositeHasher,
        ILogger<InMemoryClientRepository> logger)
    {
        ArgumentNullException.ThrowIfNull(clients);
        ArgumentNullException.ThrowIfNull(compositeHasher);
        ArgumentNullException.ThrowIfNull(logger);

        var dict = new Dictionary<string, IClientRegistration>(StringComparer.Ordinal);

        foreach (var client in clients)
        {
            ArgumentNullException.ThrowIfNull(client);
            ValidateClient(client, compositeHasher, logger);

            if (!dict.TryAdd(client.ClientId, client))
                throw new ArgumentException(
                    $"Duplicate client_id '{client.ClientId}' is not allowed.",
                    nameof(clients));
        }

        _clients = dict;
    }

    /// <inheritdoc />
    public ValueTask<IClientRegistration?> FindByClientIdAsync(
        string clientId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _clients.TryGetValue(clientId, out var client);
        return ValueTask.FromResult(client);
    }

    // ClientId charset: ASCII letters, digits, and '_', '-', '.'.
    private static readonly System.Text.RegularExpressions.Regex _clientIdPattern =
        new(@"^[A-Za-z0-9_\-.]+$", System.Text.RegularExpressions.RegexOptions.Compiled);

    private const int MaxClientIdLength = 200;
    private const int MaxRedirectUrisPerClient = 32;

    private static void ValidateClient(
        IClientRegistration client,
        CompositeClientSecretHasher compositeHasher,
        ILogger logger)
    {
        // ClientId
        if (string.IsNullOrWhiteSpace(client.ClientId))
            throw new ArgumentException("ClientId must not be null, empty, or whitespace.");
        if (client.ClientId.Length > MaxClientIdLength)
            throw new ArgumentException(
                $"ClientId '{client.ClientId}' exceeds the {MaxClientIdLength}-character limit.");
        if (!_clientIdPattern.IsMatch(client.ClientId))
            throw new ArgumentException(
                $"ClientId '{client.ClientId}' contains disallowed characters. " +
                "Allowed: ASCII letters, digits, '_', '-', '.'.");

        // Consistency: IsPublic ⇔ ClientSecret is null ⇔ AllowedTokenEndpointAuthMethods == { None }.
        // All three must agree. Mismatch would allow a confidential client to authenticate as
        // 'none', or a public client to be required to present a secret it cannot hold. Reject
        // at startup with ZeeKayDaConfigurationException (see ADR 0006 §1) — this is a
        // configuration bug, not a value-object validation error.
        var authMethods = client.AllowedTokenEndpointAuthMethods;
        var authMethodsIsExactlyNone =
            authMethods.Count == 1 && authMethods.Contains(TokenEndpointAuthMethods.None);

        if (client.IsPublic)
        {
            if (client.ClientSecret is not null)
                throw new ZeeKayDaConfigurationException(
                    $"Client '{client.ClientId}': IsPublic = true but ClientSecret is non-null. " +
                    "Public clients must not carry a stored credential.");
            if (!authMethodsIsExactlyNone)
                throw new ZeeKayDaConfigurationException(
                    $"Client '{client.ClientId}': IsPublic = true but " +
                    "AllowedTokenEndpointAuthMethods is not exactly " +
                    "{ TokenEndpointAuthMethods.None }. Public clients cannot authenticate " +
                    "at the token endpoint.");
        }
        else
        {
            if (client.ClientSecret is null)
                throw new ZeeKayDaConfigurationException(
                    $"Client '{client.ClientId}': IsPublic = false but ClientSecret is null. " +
                    "Confidential clients must carry a stored credential.");
            if (authMethods.Contains(TokenEndpointAuthMethods.None))
                throw new ZeeKayDaConfigurationException(
                    $"Client '{client.ClientId}': IsPublic = false but " +
                    "AllowedTokenEndpointAuthMethods contains " +
                    "TokenEndpointAuthMethods.None. A confidential client must not be " +
                    "permitted to skip authentication.");

            // Defence-in-depth: every confidential client's stored ClientSecret MUST reject
            // the empty string. Each framework hasher's VerifyCore enforces this explicitly
            // (e.g. Pbkdf2ClientSecretHasher rejects ReadOnlySpan<char>.IsEmpty); this check
            // catches a custom IClientSecretHasher whose VerifyCore mistakenly accepts
            // empty input. Resolved via the composite hasher injected into ValidateClient
            // — see InMemoryClientRepository constructor.
            if (compositeHasher.Verify(client.ClientSecret!, ReadOnlySpan<char>.Empty))
                throw new ArgumentException(
                    $"Client '{client.ClientId}': the configured IClientSecretHasher accepts " +
                    "the empty string against this client's stored secret. This indicates a " +
                    "broken VerifyCore implementation and is rejected as a defence-in-depth " +
                    "measure.");
        }

        // Per-value advisory warning for unrecognised token-endpoint auth methods. A custom
        // IClientSecretHasher (paired with a custom IClientSecret sub-interface) may
        // legitimately introduce a new method (e.g. tls_client_auth), so this is informational
        // rather than a configuration error. The whole-set rejection (no framework-known method
        // AND no custom hasher covers any of them) is enforced separately at startup — see §1a.
        foreach (var method in authMethods)
        {
            if (method is not TokenEndpointAuthMethods.ClientSecretBasic
                       and not TokenEndpointAuthMethods.ClientSecretPost
                       and not TokenEndpointAuthMethods.None)
            {
                logger.LogWarning(
                    "Client '{ClientId}': AllowedTokenEndpointAuthMethods contains " +
                    "'{Method}', which is not a framework-recognised constant on " +
                    "TokenEndpointAuthMethods. This is permitted (a custom " +
                    "IClientSecretHasher paired with a custom IClientSecret sub-interface " +
                    "may implement it) but will fail authentication unless such a hasher " +
                    "covers it.",
                    client.ClientId, method);
            }
        }

        // Belt-and-suspenders enum-domain check for the four enum-typed vocabularies.
        // Catches deliberate (GrantType)999-style casts that bypass C#'s type system.
        // See §1a — these checks complement, they do not replace, the type system.
        ValidateEnumDomain(client.AllowedGrantTypes, client.ClientId, nameof(IClientRegistration.AllowedGrantTypes));
        ValidateEnumDomain(client.AllowedResponseTypes, client.ClientId, nameof(IClientRegistration.AllowedResponseTypes));
        ValidateEnumDomain(client.AllowedResponseModes, client.ClientId, nameof(IClientRegistration.AllowedResponseModes));
        ValidateEnumDomain(client.AllowedPromptValues, client.ClientId, nameof(IClientRegistration.AllowedPromptValues));

        static void ValidateEnumDomain<TEnum>(IReadOnlySet<TEnum> values, string clientId, string propertyName)
            where TEnum : struct, Enum
        {
            foreach (var value in values)
            {
                if (!Enum.IsDefined(value))
                    throw new ZeeKayDaConfigurationException(
                        $"Client '{clientId}': {propertyName} contains undefined " +
                        $"{typeof(TEnum).Name} value '{value}'. This indicates an " +
                        "out-of-range cast (e.g. (GrantType)999).");
            }
        }

        // Redirect URIs
        ValidateRedirectUriSet(
            client.RedirectUris,
            client.ClientId,
            nameof(IClientRegistration.RedirectUris),
            requireAtLeastOne: true,
            logger);

        // Post-logout redirect URIs — same rules as RedirectUris, but the set may be empty
        // (a client without an end-session redirect URI is a valid configuration).
        ValidateRedirectUriSet(
            client.PostLogoutRedirectUris,
            client.ClientId,
            nameof(IClientRegistration.PostLogoutRedirectUris),
            requireAtLeastOne: false,
            logger);

        // Allowed signing algorithms — shape check only (non-empty when non-null).
        // The cross-options subset check against IdTokenOptions.SigningAlgValuesSupported
        // runs in IValidateOptions<…> at host startup (see below), because the global set
        // is not available to ValidateClient when InMemoryClientRepository is constructed
        // via DI before options have been bound for all consumers.
        if (client.AllowedSigningAlgorithms is { Count: 0 })
            throw new ZeeKayDaConfigurationException(
                $"Client '{client.ClientId}': AllowedSigningAlgorithms is non-null but empty. " +
                "Either omit the property (null = inherit IdTokenOptions.SigningAlgValuesSupported) " +
                "or provide at least one algorithm.");

        // Scopes
        foreach (var scope in client.AllowedScopes)
        {
            if (string.IsNullOrWhiteSpace(scope))
                throw new ArgumentException(
                    $"Client '{client.ClientId}': AllowedScopes must not contain empty or " +
                    "whitespace entries.");
        }
        // Note: AllowedScopes is IReadOnlySet<string> with StringComparer.Ordinal, so
        // case-variant duplicates ("openid" + "OpenID") are preserved as distinct entries and
        // are caught downstream by the scope-existence check in InMemoryScopeRepository, which
        // is also Ordinal. Document this as the intended behaviour.
    }

    // ValidateRedirectUri — see §4.

    // Shared helper for RedirectUris and PostLogoutRedirectUris. Centralising the loop
    // avoids drift between the two call sites and keeps validation messages aligned.
    private static void ValidateRedirectUriSet(
        IReadOnlySet<string> uris,
        string clientId,
        string propertyName,
        bool requireAtLeastOne,
        ILogger logger)
    {
        if (uris is null)
            throw new ArgumentException(
                $"Client '{clientId}': {propertyName} must not be null.");

        if (requireAtLeastOne && uris.Count == 0)
            throw new ArgumentException(
                $"Client '{clientId}': at least one entry must be present in {propertyName}.");

        if (uris.Count > MaxRedirectUrisPerClient)
            throw new ArgumentException(
                $"Client '{clientId}': {propertyName} may contain at most " +
                $"{MaxRedirectUrisPerClient} entries.");

        foreach (var uri in uris)
            ValidateRedirectUri(uri, clientId, logger);
    }
}
```

**Cross-options startup validation for `AllowedSigningAlgorithms`.** The *subset* check —
that every value in a non-null `AllowedSigningAlgorithms` is also present in
`IdTokenOptions.SigningAlgValuesSupported` — cannot live in `InMemoryClientRepository.ValidateClient`
because the global `IdTokenOptions` may not be bound when the repository is constructed (and a
custom `IClientRepository` would not run that code path at all). It runs instead in an
`IValidateOptions<…>` registered with `OptionsBuilder.ValidateOnStart()` — the same mechanism
ADR 0001 §6 uses for issuer validation and §6 above uses for the missing-`IClientRepository`
check. The validator resolves the registered `IClientRepository` (synchronously enumerating all
clients for the in-memory case; custom async repositories are exempt from the cross-check and
must perform their own subset validation) and the bound `IdTokenOptions`, then throws
`ZeeKayDaConfigurationException` naming the offending `client_id` and the offending algorithm if
any client's `AllowedSigningAlgorithms` contains a value not in
`IdTokenOptions.SigningAlgValuesSupported`.

Summary of the split:

| Check | Layer | Exception |
|---|---|---|
| `AllowedSigningAlgorithms` non-empty when non-null (shape) | `InMemoryClientRepository.ValidateClient` (registration time) | `ZeeKayDaConfigurationException` |
| `AllowedSigningAlgorithms ⊆ IdTokenOptions.SigningAlgValuesSupported` (cross-options) | `IValidateOptions<…>` at host startup | `ZeeKayDaConfigurationException` |

**Package ownership:**

| Concern | Package |
|---|---|
| `IClientRegistration` interface | `ZeeKayDa.Auth` |
| `ClientRegistration` sealed record | `ZeeKayDa.Auth` |
| `IClientSecret`, `IPbkdf2ClientSecret`, `Pbkdf2ClientSecret` record | `ZeeKayDa.Auth` |
| `IClientSecretHasher`, `ClientSecretHasher<TSecret>` base, `Pbkdf2ClientSecretHasher` | `ZeeKayDa.Auth` |
| `CompositeClientSecretHasher` (internal), `ClientSecretHasherOptions`, `ClientSecretHasherOptionsValidator` | `ZeeKayDa.Auth` |
| `IClientRepository` interface | `ZeeKayDa.Auth` |
| `InMemoryClientRepository` | `ZeeKayDa.Auth` |
| `ClientRegistration.CreateConfidential` / `CreatePublic` factory methods | `ZeeKayDa.Auth` |
| `AddInMemoryClients`, `AddSecretsHasher<T>(bool isDefault = false)` DI builder extensions | `ZeeKayDa.Auth.AspNetCore` |

**Fail-fast on missing repository.** `AddZeeKayDaAuth` does NOT register a default
`IClientRepository`. Per the fail-fast principle from ADR 0001 §6, the absence of a configured
repository is a fatal misconfiguration. This ADR adopts the same mechanism that ADR 0001 §6 uses
for issuer validation — an `IValidateOptions<ZeeKayDaAuthOptions>` registered with
`OptionsBuilder.ValidateOnStart()` that inspects the service collection and throws a
`ZeeKayDaConfigurationException` (see ADR 0006 §1) at host startup if no `IClientRepository` has
been registered. The exception message names the missing service and points at
`AddInMemoryClients` and the `IClientRepository` documentation.

### 7. DI wiring — `AddInMemoryClients` builder extension

Following the precedent set by `AddInMemoryScopes`, a builder extension on `ZeeKayDaAuthBuilder`
registers the in-memory repository:

```csharp
// ZeeKayDa.Auth.AspNetCore — ZeeKayDaAuthBuilderClientExtensions.cs
public static class ZeeKayDaAuthBuilderClientExtensions
{
    /// <summary>
    /// Registers an in-memory <see cref="IClientRepository"/> pre-populated with the
    /// supplied clients. Subsequent calls REPLACE the previously registered repository
    /// (last-call-wins) to keep behaviour predictable in test fixtures.
    /// </summary>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="clients">The client registrations to register.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="clients"/> is
    /// <see langword="null"/>.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddInMemoryClients(
        this ZeeKayDaAuthBuilder builder,
        IEnumerable<IClientRegistration> clients)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(clients);

        builder.Services.Replace(
            ServiceDescriptor.Singleton<IClientRepository>(sp =>
                new InMemoryClientRepository(
                    clients,
                    sp.GetRequiredService<CompositeClientSecretHasher>(),
                    sp.GetRequiredService<ILogger<InMemoryClientRepository>>())));

        return builder;
    }
}
```

**Replace semantics — last-call-wins.** `Replace` (not `TryAddSingleton`) is used — matching the
`AddInMemoryScopes` pattern — so that a second call to `AddInMemoryClients` replaces the first
registration rather than silently appending. This is the intended behaviour for test fixtures
that configure a default repository which individual tests override. The trade-off is that two
accidental `AddInMemoryClients` calls in production wiring silently keep only the last set; this
is documented as a known behaviour.

**`AddInMemoryClients` (plural) is the only client-list DI extension** in `ZeeKayDa.Auth.AspNetCore`.
There is no singular `AddInMemoryClient` DI extension — and none is planned. Ergonomic
construction of individual registrations is provided by **static factory methods on
`ClientRegistration` itself** (in `ZeeKayDa.Auth`), described below.

`AddSecretsHasher<T>(bool isDefault = false)` is the second DI extension (specified in §3.5).

**Ergonomic factory methods on `ClientRegistration`** for the two most common cases — public and
confidential clients with sensible defaults:

```csharp
namespace ZeeKayDa.Auth.Clients;

public sealed record ClientRegistration : IClientRegistration
{
    // ... existing record members ...

    /// <summary>
    /// Constructs a confidential <see cref="ClientRegistration"/>. The supplied plaintext is
    /// hashed by <paramref name="hasher"/> via <see cref="IClientSecretHasher.Create"/>; the
    /// resulting <see cref="IClientSecret"/> is stored in <see cref="ClientSecret"/>.
    /// <see cref="IsPublic"/> is set to <see langword="false"/> and
    /// <see cref="IClientRegistration.AllowedTokenEndpointAuthMethods"/> defaults to
    /// <c>{ <see cref="TokenEndpointAuthMethods.ClientSecretBasic"/> }</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Pass the framework's resolved <see cref="IClientSecretHasher"/> (typically the default
    /// <see cref="Pbkdf2ClientSecretHasher"/>) — for sample/bootstrap code, instantiate one
    /// directly; for production code that already has a DI container, resolve from DI.
    /// </para>
    /// <para>
    /// <paramref name="postLogoutRedirectUris"/> is required (no default). Pass an empty
    /// collection if the client has no end-session redirect URIs — see
    /// <see cref="IClientRegistration.PostLogoutRedirectUris"/>.
    /// </para>
    /// <para>
    /// Per-client <see cref="IClientRegistration.AllowedSigningAlgorithms"/> narrowing is
    /// intentionally not exposed on this factory (the simple-case signature would suffer);
    /// advanced consumers drop to the record initializer to set it.
    /// </para>
    /// </remarks>
    public static ClientRegistration CreateConfidential(
        IClientSecretHasher hasher,
        string clientId,
        string clientSecret,
        IEnumerable<string> redirectUris,
        IEnumerable<string> postLogoutRedirectUris,
        IEnumerable<string> allowedScopes,
        IEnumerable<GrantType>? allowedGrantTypes = null,
        IEnumerable<ResponseType>? allowedResponseTypes = null,
        IEnumerable<ResponseMode>? allowedResponseModes = null,
        IEnumerable<PromptValue>? allowedPromptValues = null,
        IEnumerable<string>? allowedTokenEndpointAuthMethods = null,
        bool enableZkdErrorCodes = false);

    /// <summary>
    /// Constructs a public <see cref="ClientRegistration"/> with <see cref="IsPublic"/> set
    /// to <see langword="true"/>, <see cref="ClientSecret"/> set to <see langword="null"/>, and
    /// <see cref="IClientRegistration.AllowedTokenEndpointAuthMethods"/> defaulted to
    /// <c>{ <see cref="TokenEndpointAuthMethods.None"/> }</c>. PKCE is enforced unconditionally
    /// by the framework.
    /// </summary>
    /// <remarks>
    /// <paramref name="postLogoutRedirectUris"/> is required (no default). Pass an empty
    /// collection if the client has no end-session redirect URIs — see
    /// <see cref="IClientRegistration.PostLogoutRedirectUris"/>.
    /// </remarks>
    public static ClientRegistration CreatePublic(
        string clientId,
        IEnumerable<string> redirectUris,
        IEnumerable<string> postLogoutRedirectUris,
        IEnumerable<string> allowedScopes,
        IEnumerable<GrantType>? allowedGrantTypes = null,
        IEnumerable<ResponseType>? allowedResponseTypes = null,
        IEnumerable<ResponseMode>? allowedResponseModes = null,
        IEnumerable<PromptValue>? allowedPromptValues = null,
        bool enableZkdErrorCodes = false);
}
```

Both factories return a `ClientRegistration` instance — they are **factory methods**, not DI
extensions. They live in `ZeeKayDa.Auth` (next to the record they construct), not in
`ZeeKayDa.Auth.AspNetCore`. Pass the resulting registrations to `AddInMemoryClients`. Production
deployments that already store a hashed `IPbkdf2ClientSecret` (loaded from configuration or a
secret store) skip the factory and assign `ClientSecret` directly via the record initializer.

**Typical wiring (simple case):**

```csharp
// Hasher used to produce IClientSecret values from plaintext at startup. For sample /
// bootstrap code, instantiate directly; production code that already has a DI scope can
// resolve IClientSecretHasher from DI instead.
var hasher = new Pbkdf2ClientSecretHasher();

builder.Services
    .AddZeeKayDaAuth(o =>
    {
        o.Issuer = "https://id.example.com";
    })
    .AddInMemoryScopes(StandardScopes.All)
    .AddInMemoryClients(
    [
        // Confidential client — server-side web application.
        // "s3cr3t" is illustrative only — never check a real secret into source.
        ClientRegistration.CreateConfidential(
            hasher: hasher,
            clientId: "web-app",
            clientSecret: "s3cr3t",
            redirectUris: ["https://app.example.com/oidc/callback"],
            postLogoutRedirectUris: ["https://app.example.com/signed-out"],
            allowedScopes: ["openid", "profile", "email"]),

        // Public client — native app (PKCE is mandatory and enforced by the framework).
        ClientRegistration.CreatePublic(
            clientId: "native-app",
            redirectUris: ["com.example.app:/callback"],
            postLogoutRedirectUris: ["com.example.app:/signed-out"],
            allowedScopes: ["openid", "profile"],
            allowedGrantTypes: [GrantType.AuthorizationCode, GrantType.RefreshToken]),

        // Confidential client — pre-hashed secret loaded from configuration / secret store.
        // No hasher needed at registration time; the secret is already an IPbkdf2ClientSecret.
        new ClientRegistration
        {
            ClientId      = "prod-backend",
            IsPublic      = false,
            ClientSecret  = new Pbkdf2ClientSecret(
                                Iterations: configuration.GetValue<int>("ProdBackend:Pbkdf2Iterations"),
                                Salt:       Convert.FromBase64String(configuration["ProdBackend:Salt"]!),
                                Hash:       Convert.FromBase64String(configuration["ProdBackend:Hash"]!)),
            RedirectUris  = new HashSet<string>(StringComparer.Ordinal)
                                { "https://backend.example.com/callback" },
            PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
            AllowedScopes = new HashSet<string>(StringComparer.Ordinal)
                                { "openid", "api.read" },
        },

        // Advanced — confidential client that only accepts PS256-signed ID tokens.
        // AllowedSigningAlgorithms is intentionally not exposed on the factory methods;
        // the per-client narrowing case drops to the record initializer.
        // new ClientRegistration {
        //     ClientId      = "specialised-client",
        //     IsPublic      = false,
        //     ClientSecret  = new Pbkdf2ClientSecret(/* iterations, salt, hash */),
        //     RedirectUris  = new HashSet<string>(StringComparer.Ordinal)
        //                         { "https://specialised.example.com/callback" },
        //     PostLogoutRedirectUris = new HashSet<string>(StringComparer.Ordinal),
        //     AllowedScopes = new HashSet<string>(StringComparer.Ordinal) { "openid" },
        //     AllowedSigningAlgorithms = new HashSet<SigningAlgorithm> { SigningAlgorithm.PS256 },
        // },
    ]);
```

**EF / NHibernate / Dapper consumers** map flat columns and project to a sub-interface in a
`[NotMapped]` (or equivalent) adapter. An EF entity sketch:

```csharp
public class ClientEntity : IClientRegistration
{
    public required string ClientId { get; set; }
    public bool IsPublic { get; set; }

    // Flat columns mapped by EF
    public int? Pbkdf2Iterations { get; set; }
    public byte[]? Pbkdf2Salt { get; set; }
    public byte[]? Pbkdf2Hash { get; set; }

    [NotMapped]
    public IClientSecret? ClientSecret =>
        IsPublic
            ? null
            : new Pbkdf2ClientSecret(Pbkdf2Iterations!.Value, Pbkdf2Salt!, Pbkdf2Hash!);

    // …RedirectUris etc. as IReadOnlySet<string> via [NotMapped] adapters or owned types…
}
```

The same pattern generalises to other algorithms — bcrypt would map flat columns
`BCryptCost` and `BCryptEncoded` and project them through a consumer-defined
`IBCryptClientSecret` getter; argon2 likewise. New algorithms drop in by adding (a) a
sub-interface, (b) a record (or any concrete shape implementing it), (c) a hasher derived
from `ClientSecretHasher<T>`, and (d) an `AddSecretsHasher<T>()` registration.

### 8. Registration-time validation summary

`InMemoryClientRepository` enforces the following rules at construction time. Any violation
throws `ArgumentException` before the application starts accepting requests:

| Rule | Spec / source |
|---|---|
| `ClientId` non-null, non-empty, non-whitespace | — |
| `ClientId` length ≤ 200 characters | S-H1 |
| `ClientId` matches `[A-Za-z0-9_\-.]+` | S-H1 |
| Consistency: `IsPublic == true` ⇔ `ClientSecret is null` ⇔ `AllowedTokenEndpointAuthMethods` exactly `{ TokenEndpointAuthMethods.None }`; `IsPublic == false` ⇔ `ClientSecret` non-null ⇔ `AllowedTokenEndpointAuthMethods` MUST NOT contain `None`. Violation throws `ZeeKayDaConfigurationException`. | A-N3 / S-N5 |
| Confidential clients: the resolved `CompositeClientSecretHasher` MUST return `false` when verifying the empty string against `client.ClientSecret` (defence-in-depth against a custom hasher that accepts empty input). | S-S3 / S-H5 |
| `Pbkdf2ClientSecretHasher.VerifyCore` rejects an empty presented `ReadOnlySpan<char>` explicitly (per-hasher empty-string defence; framework hashers MUST do the same). | §3.3 |
| `AllowedTokenEndpointAuthMethods` per-value advisory `LogWarning` when a value matches no framework-recognised constant on `TokenEndpointAuthMethods` (informational — a custom `IClientSecretHasher` paired with a custom `IClientSecret` sub-interface may legitimately introduce a new method) | §1a |
| `AllowedGrantTypes` / `AllowedResponseTypes` / `AllowedResponseModes` / `AllowedPromptValues` — every element passes `Enum.IsDefined` (catches `(GrantType)999`-style casts). Violation throws `ZeeKayDaConfigurationException`. Note: well-typed C# callers cannot produce an "unknown value" through the type system, so this is belt-and-suspenders, not the primary defence. | §1a |
| `Pbkdf2ClientSecretHasher` constructor enforces `iterations >= 100_000`; below-minimum throws `ZeeKayDaConfigurationException`. `Pbkdf2ClientSecret` records carrying values below the minimum, salts shorter than 16 bytes, or hashes of any length other than 32 bytes are rejected by `VerifyCore` returning `false`. | §3.3 / S-N3 |
| At least one entry in `AllowedTokenEndpointAuthMethods` is recognised — by either a framework constant or a registered custom `IClientSecretHasher` (whole-set startup rejection). Violation throws `ZeeKayDaConfigurationException`. | §1a |
| Hasher resolution: 0 hashers, or 2+ hashers with 0 explicit defaults, or 2+ explicit defaults all throw `ZeeKayDaConfigurationException` at startup with the exact wording specified in §3.6. | §3.5 / §3.6 |
| At least one redirect URI present | RFC 6749 §3.1.2 |
| At most 32 redirect URIs per client | S-H2 |
| Redirect URI is a valid absolute URI | RFC 6749 §3.1.2 |
| Redirect URI MUST NOT contain a fragment component | RFC 6749 §3.1.2 |
| Redirect URI MUST NOT contain a userinfo component | S-R2 / S-S6 |
| Redirect URI MUST NOT contain a `.` or `..` path segment (ambiguous canonicalisation) | S-N2 |
| Redirect URI scheme is one of: `https`; `http` (loopback only); a private-use scheme containing `.` and not in the forbidden list | RFC 8252 §7.1, §7.3 / RFC 9700 §2.1 / S-R2 |
| `PostLogoutRedirectUris` declared (non-null); same per-entry rule set as `RedirectUris` (§4 Rules 2–5); 32-entry cap; empty set permitted | §4 (rule set), OIDC RP-Initiated Logout 1.0 §2 |
| `AllowedSigningAlgorithms` non-null ⇒ non-empty (shape) — throws `ZeeKayDaConfigurationException` | OIDC Core §3.1.3.7 |
| `AllowedSigningAlgorithms ⊆ IdTokenOptions.SigningAlgValuesSupported` — cross-options check at host startup via `IValidateOptions<…>`, throws `ZeeKayDaConfigurationException` | OIDC Core §3.1.3.7 |
| `localhost` host emits an advisory `LogWarning` recommending the IP literal | RFC 8252 §8.3 / S-S2 |
| `AllowedScopes` contains no empty/whitespace entries | S-H5 |
| No duplicate `client_id` within the repository | — |

Request-time validation (binding constraints on the future authorization-endpoint and
token-endpoint ADRs, not implemented here) additionally enforces:

- Exact redirect URI match (with the loopback-port exception of §4 Rule 1).
- PKCE presence for all clients (OAuth 2.1 §7.6).
- Grant type and response type membership against the client's allowed sets.
- Response mode membership against the client's allowed set (`ResponseMode.Fragment` is never accepted regardless of the client's set).
- Token-endpoint auth method membership against `AllowedTokenEndpointAuthMethods`.
- Scope intersection per §5.
- Client authentication via `CompositeClientSecretHasher.Verify(client.ClientSecret!, presented)`,
  with a dummy-verify call on the unknown-client path (§3.8 rule 3, §3b) AND an additional
  `PadTiming()` call on the known-client failure path so every `invalid_client` outcome's
  wall-clock time is dominated by the resolved default hasher's work factor — see the §3b
  "Timing padding for fast hashers" constraint.
- Refresh tokens issued only to clients whose `AllowedGrantTypes` includes `GrantType.RefreshToken`
  (S-H3).

### 9. Forward-compatibility with RFC 7591 dynamic client registration

Dynamic registration is out of scope for v1 (see Rejected Alternatives). The chosen
`IClientRepository` abstraction is forward-compatible with a future `DynamicClientRepository`
**decorator** that wraps an internal writable static repository and exposes the RFC 7591
`/register` endpoint. The decorator's responsibilities will be cleanly split: an internal
mutable `IWritableClientRepository` handles persistence; a separate
`IDynamicClientRegistrationPolicy` interface gates which metadata fields a self-registering
client may set, what scopes/grant types it may request, and any rate limiting. This separation
keeps the policy decisions testable in isolation from storage and means the static-registration
guarantees this ADR establishes are not eroded by the dynamic-registration code path.

---

## Rejected Alternatives

### `IReadOnlyDictionary<string, IClientRegistration>` instead of `IClientRepository`

**Rejected.** Exposing a plain dictionary as the extension point has several problems: (a) it
couples the abstraction to an in-memory model — a consumer backed by a database cannot satisfy
an `IReadOnlyDictionary` contract without materialising all clients into memory at startup, which
is unsafe for large client sets; (b) it does not support async I/O, meaning any repository that
performs network or disk I/O on lookup would have to block a thread; (c) it leaks internal
structure — callers could enumerate all registered clients, which may be undesirable. The
`IClientRepository` interface with a single `FindByClientIdAsync` method is minimal, async-native,
and encapsulates the repository implementation completely. It follows the same design reasoning
as `IScopeRepository`.

### Strings for all per-client protocol vocabularies

**Rejected.** An earlier draft of this ADR typed all per-client protocol-vocabulary fields
(`AllowedGrantTypes`, `AllowedResponseTypes`, `AllowedResponseModes`, `AllowedPromptValues`,
`AllowedTokenEndpointAuthMethods`) as `IReadOnlySet<string>`, on the grounds that the spec
ecosystem keeps adding new values (extension grant types like
`urn:ietf:params:oauth:grant-type:device_code`, JARM's `form_post.jwt`, MTLS auth methods).
That was a misapplication of the open-set argument: for `grant_type`, `response_type`,
`response_mode`, and `prompt`, a new wire value cannot be honoured without framework-side
implementation, so strings only erased compile-time safety without buying any real
extensibility. The corrected distinction — enum when framework changes are required, `string`
+ constants only when a public extension point carries the new value end-to-end — is
captured in §1a. The four enum-typed vocabularies use `GrantType`, `ResponseType`,
`ResponseMode`, and the new `PromptValue`. `AllowedTokenEndpointAuthMethods` remains
`IReadOnlySet<string>` because `IClientSecretHasher` (paired with `IClientSecret`
sub-interfaces) is a public extension point that genuinely supports new methods (e.g.
`tls_client_auth`) without core changes; magic strings are avoided by the
`TokenEndpointAuthMethods` constants class.

### Closed enums (`GrantType`, `ResponseType`, …) used for *all* per-client fields including auth methods

**Rejected.** Symmetric to the above: unifying `AllowedTokenEndpointAuthMethods` onto the
existing `TokenEndpointAuthMethod` enum, or onto any other closed enum, would foreclose the
custom-`IClientSecretHasher` extension path. The two `TokenEndpointAuthMethod*` types
(the enum for discovery metadata, the constants class for per-client config) are kept
separate by design — see §1a.

### `string? ClientSecret` directly on `IClientRegistration`

**Rejected.** See §3. The earliest draft used `string? ClientSecret` with prose saying "store
hashed in production". This is ambiguous (the type cannot tell plaintext from a hash), pushes
fixed-time comparison out into every custom repository (where it is highly likely to be done
wrong), and creates a sample-code trap — `ClientSecret = "s3cr3t"` looks production-ready in
IntelliSense. It was replaced first by an `IClientSecretVerifier` abstraction, then (this
revision) by the cleaner `IClientSecret` data marker + `IClientSecretHasher` service split.

### Embedding `IClientSecretVerifier` (or any service) on `IClientRegistration`

**Rejected.** Earlier drafts placed an `IClientSecretVerifier? SecretVerifier { get; }` property
directly on the registration interface. Three problems made this untenable:

- It conflated configuration data ("what a client is") with a behavioural service ("how to verify
  its credential") on the same type.
- It was hostile to ORM-mapped implementations: mapping a polymorphic interface property to an EF
  entity (or NHibernate component, or Dapper projection) requires owned-type acrobatics, value
  converters, or TPH discriminators — disproportionate machinery for what should be flat columns.
- A consumer could not legitimately implement `IClientRegistration` without picking which
  behavioural verifier their entity carried, even though the entity itself ought to be passive
  data.

The replacement design splits cleanly: `IClientRegistration.ClientSecret` exposes an
`IClientSecret?` (pure data marker, ORM-friendly), and verification + creation are handled by
`IClientSecretHasher` registrations dispatched through a framework-internal composite. EF/
NHibernate/Dapper consumers map flat columns and project to a sub-interface in a `[NotMapped]`
getter; the framework never sees the storage shape.

### A single `string Algorithm` discriminator on `IClientSecret` with switch-based dispatch

**Rejected.** A flatter shape — one concrete `ClientSecret(string Algorithm, byte[] Salt,
byte[] Hash, int Iterations)` record with the hasher switching on `Algorithm` — was
considered. It was rejected because:

- Different algorithms have different parameter shapes (PBKDF2: iterations; bcrypt: combined
  cost+salt+hash string; argon2id: memory cost + parallelism + iterations). A single record
  forces nullable fields and per-algorithm conventions on which fields apply.
- The hasher would carry a switch over algorithm strings — an abstraction leak that defeats
  the goal of "the hasher doesn't need to figure it out".
- Adding a new algorithm would require both a new record discriminator value and modifications
  to the central hasher dispatch.

The marker-hierarchy approach (`IClientSecret` + `IPbkdf2ClientSecret` + consumer-defined
sub-interfaces) gives each algorithm its own data shape and dispatches via `secret is TSecret`
polymorphism handled by the generic `ClientSecretHasher<T>` base. New algorithms drop in by
adding (a) a sub-interface, (b) a record implementation, (c) an `IClientSecretHasher` derived
from `ClientSecretHasher<T>`, all wired via `AddSecretsHasher<T>()`.

### Record type as the sole representation (no `IClientRegistration` interface)

**Rejected.** A sealed `ClientRegistration` record with no interface would require every custom
`IClientRepository` to return `ClientRegistration` instances, forcing consumers to copy their
entity data into a framework type on every lookup. For applications that already have a `Client`
entity in their domain model (e.g. Entity Framework entities), this would create a redundant
mapping layer on the hot path of every authorization request. An interface allows the consumer's
entity type to implement `IClientRegistration` directly, incurring zero allocation for the
wrapper.

### Separate types for public and confidential clients

**Rejected.** Two separate types — `PublicClientRegistration` and
`ConfidentialClientRegistration` — were considered to enforce at compile-time that public clients
never have a stored credential and confidential clients always do. This would be type-safe but
imposes a discriminated-union return type on `IClientRepository` (either two separate `Find*`
methods or a `OneOf<>` / base-type return). The framework's request validation pipeline would
need to downcast to access the stored secret or a client-type enum. The added type complexity is
not proportionate to the safety benefit, especially since the declared `IsPublic` property
already makes the distinction clear and the validation rules in §6/§8 enforce correctness at
registration time. The single-interface approach is simpler and equally safe.

### Supporting the `fragment` response mode

**Rejected.** `fragment` response mode is intentionally not supported. It exists to serve the
implicit flow, which OAuth 2.1 §7 removes, and it has well-documented downsides: the
authorization code (or, historically, tokens) is exposed to any script running on the redirect
page via `window.location.hash`, and it interacts poorly with same-document navigation. The
`AllowedResponseModes` set defaults to `{ ResponseMode.Query, ResponseMode.FormPost }` and the
request-time validator rejects any request asking for `response_mode=fragment` regardless of
what the client's allowed set contains. This is documented prominently in §1 and the docs
note D6.

### Dynamic client registration (RFC 7591) as the primary registration mechanism

**Rejected** for v1. RFC 7591 defines a `/register` endpoint that clients can call at runtime to
self-register. Implementing RFC 7591 correctly involves: registration token management, optional
registration management endpoints (RFC 7592), policy enforcement on allowed metadata fields, and
storage of dynamically registered clients distinct from statically configured ones.
Supporting dynamic registration in v1 would significantly increase scope, add multiple new
attack surface areas (unauthenticated registration, registration flooding), and complicate the
startup-validation guarantees this ADR establishes. Static registration is sufficient for the
initial target audience. The `IClientRepository` abstraction is deliberately forward-compatible
with a future `DynamicClientRepository` decorator (see §9).

### Abstract base class instead of interface

**Rejected.** An abstract `ClientRegistrationBase` class would constrain implementors to single
inheritance — unnecessarily restrictive for a consumer whose client entity already extends a
framework type (e.g. an EF entity extending `AuditableEntity`). An interface imposes no
inheritance constraint and is the idiomatic .NET choice for a capability contract.

---

## Consequences

### Positive

- `IClientRegistration` as an interface allows custom `IClientRepository` implementations to
  return their own entity types without any mapping layer, keeping the authorization request hot
  path allocation-minimal.
- `ClientRegistration` sealed record with `required` init-only properties provides compile-time
  enforcement of mandatory fields without constructor overloads, and `with`-expression copying
  simplifies test setup.
- Fragment, userinfo, and scheme-allowlist checks enforced at startup (in
  `InMemoryClientRepository`) mean that a misconfigured production deployment fails loudly
  before serving its first request, not silently on the first authorization attempt.
- The scheme allowlist (HTTPS / loopback HTTP / reverse-DNS private-use) is fail-closed: future
  browser-introduced URI schemes cannot accidentally become valid redirect targets without an
  explicit framework change.
- The loopback-port exception (§4 Rule 1) makes RFC 8252 §7.3 native-app deployments work
  correctly without sacrificing the exact-string match guarantee for every other client type.
- The `IClientSecret` / `IClientSecretHasher` split keeps registration data pure: an
  `IClientRegistration` carries only data, no service references. ORM consumers (EF,
  NHibernate, Dapper) map primitive columns and project to a sub-interface in a
  `[NotMapped]` adapter; no polymorphic property mapping or owned-type acrobatics are
  required.
- The framework never sees or compares plaintext beyond `IClientSecretHasher.Create` /
  `Verify`. `Pbkdf2ClientSecretHasher` provides a built-in production-grade default with
  600k PBKDF2-HMAC-SHA256 iterations; custom hashers (KMS-backed, HSM-backed, bcrypt,
  argon2id) plug in via `AddSecretsHasher<T>()` without touching framework internals.
- New hashing algorithms can be added by consumers without framework changes — drop in a
  sub-interface, a record, and a `ClientSecretHasher<T>` subclass; register with
  `AddSecretsHasher<T>()`. The composite-hasher dispatch keeps the verification path
  switch-free in framework and consumer code; the only "switch" is the type pattern in
  `ClientSecretHasher<T>.CanHandle`, contained inside one base class.
- The composite-hasher timing-padding requirement (`PadTiming()` on every failure path)
  makes the wall-clock time of "unknown client", "wrong secret", and
  "no-hasher-recognises-this-secret" all comparable to the resolved default hasher's
  success path, denying an attacker a client-id enumeration oracle even when faster
  custom hashers are registered.
- The `AddInMemoryClients` builder extension follows the exact pattern established by
  `AddInMemoryScopes`, keeping the DI registration API consistent and predictable for
  consumers. `AddSecretsHasher<T>(bool isDefault = false)` follows the same style.
- `IsPublic` as a declared property (mirroring `PostLogoutRedirectUris`) forces consumers
  to make the public/confidential intent explicit at the type level, eliminating a class
  of silent-default configuration bugs.
- PKCE enforced unconditionally (no per-client opt-out) means there is no path to a less-secure
  configuration, consistent with OAuth 2.1 §7.6 and the project's "secure by default" principle.
- The scope intersection rule (client `AllowedScopes` as a hard cap, applied both at request
  validation and again inside `GrantAsync`) means that a host bug passing unvalidated scopes to
  `GrantAsync` cannot grant scopes the client was not registered for — the framework is the last
  line of defence.
- `IClientRepository` is async-native (`ValueTask`) from the start; consumers will never face a
  breaking change when moving from in-memory to a database-backed repository.
- v1 ships first-class client configuration for **OIDC RP-Initiated Logout 1.0**
  (`PostLogoutRedirectUris`, validated with the same rule set as `RedirectUris` via a shared
  helper) and for **per-client ID-token signing-algorithm narrowing**
  (`AllowedSigningAlgorithms`, with `null` = inherit the framework-wide default). Both are
  threaded into the existing registration- and startup-validation machinery so misconfiguration
  fails loudly before the first request is served.
- Per-client protocol-vocabulary properties for `grant_type`, `response_type`,
  `response_mode`, and `prompt` are typed as `IReadOnlySet<TEnum>` rather than
  `IReadOnlySet<string>`. Compile-time enforcement prevents typos (e.g.
  `"authrozation_code"`) that would otherwise surface only at request time — or, worse,
  slip through if the validator silently dropped unknown strings. The `Enum.IsDefined`
  belt-and-suspenders check defends against deliberate `(GrantType)999`-style out-of-range
  casts. `AllowedTokenEndpointAuthMethods` remains `IReadOnlySet<string>` — the one
  genuinely open case — so a third party can introduce a new auth method (e.g.
  `tls_client_auth`) end-to-end via a custom `IClientSecretHasher` without any framework
  code change; the `TokenEndpointAuthMethods` constants class eliminates magic strings for
  the framework-recognised values. See §1a.

### Negative / Trade-offs

- Custom `IClientRegistration` implementations that do not go through `InMemoryClientRepository`
  bypass registration-time validation. The framework performs belt-and-suspenders request-time
  checks, but consumers providing custom repositories must be aware that they own the
  responsibility for ensuring their registrations meet the spec requirements documented in §4,
  §6, and §8. Documentation must make this explicit (doc requirement D1).
- `Replace` semantics in `AddInMemoryClients` means a second call silently replaces the first
  registration. This is intentional for test flexibility but could be surprising in production
  code where two `AddInMemoryClients` calls are accidentally present. A future debug-mode
  assertion or log warning when replacing an existing repository could be added without breaking
  the public contract.
- Consumers wanting bcrypt / argon2id / a KMS-backed hasher must implement four small types:
  the sub-interface, a record (or other concrete shape) implementing it, an
  `IClientSecretHasher` (typically deriving from `ClientSecretHasher<T>`), and an
  `AddSecretsHasher<T>()` registration. Mitigated by `ClientSecretHasher<T>` reducing the
  hasher to two `*Core` overrides; the boilerplate is small and bounded.
- Multiple registered hashers with no explicit default fail at startup with
  `ZeeKayDaConfigurationException`. Strict — but the alternative is silent ambiguity about
  which algorithm new secrets are created with, which is the kind of "invisible coin flip"
  this project's security posture explicitly avoids.
- `CompositeClientSecretHasher` is registered as the concrete type, NOT as
  `IClientSecretHasher`, to avoid self-injection through `IEnumerable<IClientSecretHasher>`
  and the resulting infinite recursion. Documented as a hard rule on the type's XML doc;
  consumers must not expose the composite as the interface.
- Consumers migrating from any string-based prototype of `AllowedGrantTypes`,
  `AllowedResponseTypes`, `AllowedResponseModes`, or `AllowedPromptValues` (including the
  prior pass of this ADR) must replace string literals such as `"authorization_code"` and
  `"select_account"` with the corresponding enum members (`GrantType.AuthorizationCode`,
  `PromptValue.SelectAccount`, …). This is a source-breaking change, accepted because the
  ADR is still **Draft** and no consumer code has been written against the v1 interface yet.
  Once the ADR moves to Accepted the property shapes are frozen.
- The shift from `IClientSecretVerifier? SecretVerifier` (prior pass) to
  `IClientSecret? ClientSecret` plus `IClientSecretHasher` services is a source-breaking
  change relative to the prior pass of this ADR. Acceptable because the ADR is still
  **Draft** and the prior pass had not yet shipped. Once the ADR moves to Accepted the
  shape is frozen.
- Promoting `IsPublic` from a default-interface-method derived from `ClientSecret is null`
  to a declared `required` property forces every existing prototype implementation to add
  the property explicitly. Same justification as the binary-breaking note for
  `PostLogoutRedirectUris`: silent defaults would convert configuration omission into a
  security-relevant runtime behaviour, and the ADR is still Draft.
- Not implementing RFC 7591 dynamic client registration in v1 limits use cases where clients
  self-register (e.g., multi-tenant SaaS where each tenant's application registers itself). This
  is a deliberate scope decision that can be addressed by a future `ZeeKayDa.Auth.DynamicClients`
  package via the decorator pattern outlined in §9 without touching the interfaces defined here.
- Promoting `PostLogoutRedirectUris` as a **non-DIM declared** member on `IClientRegistration`
  (rather than as a default interface member returning an empty set) is a binary-breaking change
  for any pre-existing `IClientRegistration` implementation outside the framework. The deliberate
  choice (silent empty-set defaults would create a hard-to-diagnose end-session-rejection bug)
  outweighs the cost because this ADR is still **Draft** and no consumer code has been written
  against the v1 interface yet. Once the ADR moves to Accepted the property's shape is frozen.
- Adding `PostLogoutRedirectUris` to both `CreateConfidential` and `CreatePublic` lengthens the
  required-parameter list of the simplest happy-path factory by one. The trade-off is judged
  acceptable because RP-Initiated Logout configuration is part of the OIDC baseline most
  consumers will eventually want, and an explicit `[]` at the call site is preferable to a
  hidden empty-set default that silently disables the end-session endpoint.
- `CreateConfidential` now requires an `IClientSecretHasher` parameter (the hasher used to
  produce the `IClientSecret` from the supplied plaintext). This makes the simplest
  bootstrap snippet a two-step (`var hasher = new Pbkdf2ClientSecretHasher(); …`) but the
  alternative — a hidden static default — would have re-introduced the same kind of
  silent-default problem the rest of the design avoids.

### Documentation requirements

The following documentation tasks fall out of this ADR and must be tracked for the docs agent's
follow-up PR:

- **D1.** A "Custom `IClientRepository` implementer's contract" page covering: the parametrised-
  lookup requirement (no SQL concatenation), the `null`-not-throw rule for unknown clients, the
  registration validation rules the implementation is responsible for, and an example skeleton.
- **D2.** Storing client secrets across ORMs — worked examples for EF Core
  (`IPbkdf2ClientSecret` via flat `Pbkdf2Iterations` / `Pbkdf2Salt` / `Pbkdf2Hash` columns
  projected through a `[NotMapped]` getter), NHibernate (component mapping), and Dapper
  (projection in the query). Includes the EF entity sketch from §7 and a guide to
  implementing a new hasher: define the sub-interface, define the record (or other
  concrete shape), subclass `ClientSecretHasher<TSecret>`, register with
  `AddSecretsHasher<T>()` (with `isDefault: true` if it should be the create-time default).
  Includes a recommendation against storing plaintext secrets at rest.
- **D3.** A prominent warning in every sample-code block that uses a plaintext secret
  literal (e.g. `clientSecret: "s3cr3t"` in a `CreateConfidential` call) noting that the
  literal is illustrative only and unsuitable for production.
- **D4.** A note on `localhost` vs `127.0.0.1` citing RFC 8252 §8.3 and explaining why the
  framework emits an advisory warning on `localhost`.
- **D5.** Update `SECURITY.md` (or add a new `docs/security/redirect-uri-validation.md`)
  capturing the scheme allowlist, the loopback-port exception, the userinfo prohibition, the
  edge-case matrix from §4, and the threat model that motivates each rule.
- **D6.** A `AllowedResponseModes` doc note explaining that `fragment` is intentionally
  unsupported and pointing at the Rejected Alternatives entry above.
- **D7.** A PKCE-mandatory FAQ entry citing RFC 9700 §2.1.1 and OAuth 2.1 §7.6, explaining why
  there is no per-client `RequirePkce` opt-out.

---

## Spec References

| Spec | Section | Relevance |
|---|---|---|
| RFC 6749 | §2 | Client types — public vs confidential |
| RFC 6749 | §3.1.2 | Redirection endpoint — URI requirements, fragment prohibition |
| RFC 6749 | §4.1.2.1 | `invalid_scope` error response |
| RFC 9700 | §2.1 | OAuth 2.0 Security BCP — redirect URI exact matching, HTTPS requirement |
| RFC 9700 | §2.1.1 | PKCE required for all clients |
| RFC 9700 | §2.1.2 | PAR considerations for confidential clients |
| RFC 8252 | §7.1 | Native apps — private-use URI scheme redirection |
| RFC 8252 | §7.3 | Native apps — loopback IP redirection (port-agnostic match) |
| RFC 8252 | §8.3 | Native apps — DNS rebinding & `localhost` considerations |
| RFC 7591 | (whole doc) | Dynamic client registration — informational; out of scope for v1 |
| RFC 9126 | (whole doc) | Pushed Authorization Requests (PAR) — deferred to v2 |
| RFC 7515 | §4.1.1 | JWS `alg` header — vocabulary for `AllowedSigningAlgorithms` |
| OIDC RP-Initiated Logout 1.0 | §2 | `post_logout_redirect_uri` parameter — `PostLogoutRedirectUris` |
| OIDC Core 1.0 | §3.1.2.1 | `prompt` parameter values — vocabulary for `PromptValue` enum |
| OIDC Core 1.0 | §3.1.3.7 | ID Token validation — `alg` matching against client-allowed set |
| OAuth 2.1 draft | §7 | Implicit and ROPC flows removed |
| OAuth 2.1 draft | §7.6 | PKCE mandatory for all clients |

---

## Revision history

- **2026-06-07 (this revision)** — incorporates architect review findings **A-R1 through A-S8**
  and security review findings **S-R1 through S-H6**. Material changes:
  - Replaced `string? ClientSecret` with `IClientSecretVerifier? SecretVerifier`
    (`PlaintextClientSecretVerifier`, `Pbkdf2ClientSecretVerifier`).
  - Renamed `IClientStore` → `IClientRepository` and `InMemoryClientStore` →
    `InMemoryClientRepository` to match existing project convention.
  - Resolved the §5 scope-intersection contradiction: silent drop, then `invalid_scope` if the
    effective set is empty.
  - Replaced the buggy `[::1]` host-string IPv6 check with `IPAddress.IsLoopback`.
  - Added a scheme allowlist (HTTPS / loopback HTTP / private-use with `.` minus a forbidden
    list) and the RFC 8252 §7.3 loopback-port exception at request time.
  - Removed `fragment` from default response modes and from supported response modes; added a
    Rejected Alternatives entry.
  - Added `AllowedTokenEndpointAuthMethods`, charset/length limits on `ClientId`, a 32-URI
    cap, and the userinfo-component prohibition.
  - Added §1a (why string sets, not enums), §3b (client enumeration mitigation), §9 (RFC 7591
    forward-compatibility via decorator).
  - Added the locked-down URI edge-case matrix in §4.
  - Specified the fail-fast mechanism (`OptionsBuilder.ValidateOnStart()` →
    `ZeeKayDaConfigurationException` per ADR 0006 §1).
  - Listed deferred-to-v2 fields (`ClientName`, `LogoUri`, `PolicyUri`, `TosUri`,
    `PostLogoutRedirectUris`, `RequirePushedAuthorizationRequests`).
  - Added the "Documentation requirements" subsection (D1–D7).
- **2026-06-07 (second tightening pass, same date)** — incorporates the architect re-review
  findings **A-N1 through A-N5** and the security re-review findings **S-N1 through S-N6**
  plus the precision nits. Material changes:
  - **A-N1 / A-N2** — removed the contradictory "may be introduced in a future version" note
    about a singular DI helper; reframed `AddInMemoryClient` as **static factory methods on
    `ClientRegistration`**: `CreateConfidential(...)` and `CreatePublic(...)`. Updated the §7
    sample to use them. `AddInMemoryClients` (plural) remains the only DI extension.
  - **A-N3 / S-N5** — added `SecretVerifier` ↔ `AllowedTokenEndpointAuthMethods` consistency
    check at registration time (`ZeeKayDaConfigurationException` on mismatch); reflected in
    §6 `ValidateClient` and §8.
  - **A-N4 / S-N3** — fully specified `Pbkdf2ClientSecretVerifier` parameters
    (PBKDF2-HMAC-SHA256, 600k default / 100k minimum iterations, ≥16-byte salt, 32-byte hash)
    and introduced the explicit `(int iterations, byte[] salt, byte[] hash)` constructor for
    loading pre-hashed credentials; documented `Create(string)` as the salt-generating
    convenience factory.
  - **A-N5** / §1a precision nit — reframed §1a request-time mapping as a binding forward
    constraint; added the rule that `AllowedTokenEndpointAuthMethods` with no framework-known
    methods must reject the client at startup (no silent fall-through to "no authentication").
  - **S-N1** — added the "Timing padding for fast verifiers" binding forward constraint in §3b
    (dummy PBKDF2 verifier must also pad the known-client failure path for non-PBKDF2
    verifiers). Reframed `PlaintextClientSecretVerifier` guidance to managed-secret-store
    deployments and added a registration-time `LogWarning` when any client uses it.
  - **S-N2** — added the `.`/`..` path-segment check to `ValidateRedirectUri` and updated the
    §4 edge-case matrix row to reference the implementation.
  - **S-N4** — tightened `IClientSecretVerifier` XML doc with four binding rules: MUST NOT
    throw; MUST NOT log/expose the secret; MUST be thread-safe; SHOULD redact `ToString()`.
  - **S-N6** — added an explicit rate-limiting note to §3b stating that throttling is the
    operator's responsibility and a future ADR will expose hooks.
  - **§4 Rule 3 precision nit** — clarified that the `.`-in-scheme check is a *structural
    proxy* for RFC 8252 §7.1 reverse-DNS ownership; operators remain responsible for not
    picking someone else's reverse-DNS scheme.
  - **§6 `IClientRepository` precision nit** — added "MUST NOT throw for malformed
    `client_id` input — return `null`" alongside the existing unknown-`client_id` rule.
- **2026-06-07 (third pass — v1-promotion of two deferred-to-v2 properties, same date)** —
  promotes `PostLogoutRedirectUris` and `AllowedSigningAlgorithms` from the deferred-to-v2 list
  to first-class v1 members on `IClientRegistration`. Material changes:
  - Removed both entries from the §1 deferred-to-v2 list.
  - Added `PostLogoutRedirectUris` as a **non-DIM declared** `IReadOnlySet<string>` on
    `IClientRegistration` and as a `required` init-only property on `ClientRegistration`
    (matching `RedirectUris`' explicit-empty treatment). Documented the binary-breaking
    nature in Consequences/Negative; acceptable because the ADR is still Draft.
  - Added `AllowedSigningAlgorithms` as a DIM returning `null` (= inherit
    `IdTokenOptions.SigningAlgValuesSupported`) on `IClientRegistration` and as a nullable
    init-only property on `ClientRegistration`. Non-breaking addition for future
    `IClientRegistration` implementations.
  - §4: same scheme allowlist / no-fragment / no-userinfo / no-`.`/`..` rules now apply to
    `PostLogoutRedirectUris`. §6: factored out `ValidateRedirectUriSet` helper used by both
    `RedirectUris` (≥1 required) and `PostLogoutRedirectUris` (empty permitted); both honour
    the 32-entry cap.
  - §6: split `AllowedSigningAlgorithms` validation across two layers — shape check
    (non-empty when non-null) runs in `InMemoryClientRepository.ValidateClient`; cross-options
    subset check against `IdTokenOptions.SigningAlgValuesSupported` runs in
    `IValidateOptions<…>` at host startup. Both throw `ZeeKayDaConfigurationException`.
  - §7: `CreateConfidential` and `CreatePublic` now take `postLogoutRedirectUris` as a
    required parameter (no default), positioned next to `redirectUris`. Sample wiring
    populates `PostLogoutRedirectUris` for every client (HTTPS for confidential/SPA,
    reverse-DNS private-use for the native-app example). `AllowedSigningAlgorithms` is
    intentionally **not** added to the factories; an advanced-narrowing example using the
    record initializer is shown as a commented sample.
  - §8: added rows for `PostLogoutRedirectUris` validation, `AllowedSigningAlgorithms`
    shape check, and the cross-options subset check.
  - Spec References: replaced the `OIDC RP-Initiated Logout 1.0 (whole doc) — deferred to v2`
    row with a §2 citation for `post_logout_redirect_uri`. Added OIDC Core 1.0 §3.1.3.7 (ID
    Token validation `alg` matching) and RFC 7515 §4.1.1 (JWS `alg` header).
  - Consequences: positive entry noting v1 now ships RP-Initiated Logout client config and
    per-client ID-token signing-algorithm narrowing; negative entries on the binary-breaking
    non-DIM choice for `PostLogoutRedirectUris` and the extra factory parameter.
- **2026-06-07 (fourth pass — enums vs strings correction, same date)** — corrects the §1a
  rationale. The "open set / extensibility" argument only holds when a new value can be
  added without ZeeKayDa framework code changes; that is genuinely true only for
  `AllowedTokenEndpointAuthMethods` (covered by the custom `IClientSecretVerifier` extension
  point). For `grant_type`, `response_type`, `response_mode`, and `prompt`, a new value
  cannot work without framework-side implementation, so strings only erased compile-time
  safety. Material changes:
  - §1: switched `AllowedGrantTypes`, `AllowedResponseTypes`, `AllowedResponseModes`, and
    `AllowedPromptValues` to `IReadOnlySet<GrantType>` / `IReadOnlySet<ResponseType>` /
    `IReadOnlySet<ResponseMode>` / `IReadOnlySet<PromptValue>` on both `IClientRegistration`
    and `ClientRegistration`. `AllowedTokenEndpointAuthMethods` remains
    `IReadOnlySet<string>` — the one genuinely open extension point.
  - §1a: rewrote rationale around the "can a new value be supported without framework
    changes?" test. Removed the previous extension-grant-type and `form_post.jwt` (JARM)
    examples, which were misapplications of the open-set argument (both require framework
    support). Replaced with the `tls_client_auth` example for the genuinely-open case.
  - Specified a new `PromptValue` enum (members `None`, `Login`, `Consent`, `SelectAccount`,
    per OIDC Core 1.0 §3.1.2.1) to be created in `src/ZeeKayDa.Auth/PromptValue.cs`,
    modelled on the existing `ResponseMode.cs` pattern. The `.cs` file is created by the
    developer during implementation; the ADR fixes the shape.
  - Specified a new `TokenEndpointAuthMethods` public static constants class
    (`ClientSecretBasic`, `ClientSecretPost`, `None`) to be created in
    `src/ZeeKayDa.Auth/TokenEndpointAuthMethods.cs`, so consumers reference constants
    instead of magic strings. Explicit one-line note distinguishing this constants class
    from the closed `TokenEndpointAuthMethod` *enum* (discovery-metadata advertisement) so
    a future reader does not unify them.
  - §2: updated default initializers to use enum-typed `HashSet<TEnum>` and
    `{ TokenEndpointAuthMethods.ClientSecretBasic }` for the auth-method default.
  - §6 `ValidateClient`: reworked the `SecretVerifier ⇔ AllowedTokenEndpointAuthMethods`
    consistency check to reference `TokenEndpointAuthMethods.None` instead of the `"none"`
    literal. Removed string-specific empty/whitespace checks for the four enum-typed
    fields. Added a per-value `LogWarning` for unrecognised auth methods (informational —
    a custom verifier may legitimately introduce them). Added an `Enum.IsDefined`-based
    belt-and-suspenders check that rejects undefined enum values (catches
    `(GrantType)999`-style casts) with `ZeeKayDaConfigurationException`.
  - §7: `CreateConfidential` / `CreatePublic` parameter types updated to
    `IEnumerable<GrantType>?`, `IEnumerable<ResponseType>?`, `IEnumerable<ResponseMode>?`,
    `IEnumerable<PromptValue>?`. Sample wiring updated to use
    `GrantType.AuthorizationCode`, `GrantType.RefreshToken`, etc. instead of string
    literals.
  - §8: updated consistency-check row to reference `TokenEndpointAuthMethods.None`. Added
    rows for the per-value auth-method advisory warning and the `Enum.IsDefined` check.
    Updated request-time bullet for `ResponseMode.Fragment` and the refresh-token check
    to reference `GrantType.RefreshToken`.
  - Rejected Alternatives: replaced the old "Closed enums on per-client fields" entry with
    a new "Strings for all per-client protocol vocabularies" entry explaining the
    misapplication of the open-set argument, plus a complementary entry rejecting the
    inverse (unifying `AllowedTokenEndpointAuthMethods` onto a closed enum) because doing
    so would foreclose the custom-`IClientSecretVerifier` extension path.
  - Consequences: moved the (formerly Negative) trade-off bullet on enum typing to
    Positive; added a Negative migration bullet noting that string-literal callers must
    move to enum members (source-breaking, acceptable while the ADR is Draft).
  - Spec References: added OIDC Core 1.0 §3.1.2.1 (prompt parameter values).
- **2026-06-07 (fifth pass — secret hashing model rewrite, same date):** Replaced the
  `IClientSecretVerifier` / `PlaintextClientSecretVerifier` / `Pbkdf2ClientSecretVerifier`
  design (verifier-on-registration) with a pure-data `IClientSecret` marker hierarchy
  (`IClientSecret`, `IPbkdf2ClientSecret`, `Pbkdf2ClientSecret` record) plus a separate
  `IClientSecretHasher` service contract (with a `ClientSecretHasher<TSecret>` generic
  base for ergonomics), dispatched through a framework-internal `CompositeClientSecretHasher`.
  Added `AddSecretsHasher<T>(isDefault)` builder extension with explicit startup-validation
  rules for resolving the default hasher when multiple are registered (resolution table and
  exact exception wording in §3.6). Renamed `IClientRegistration.IsPublicClient` → `IsPublic`
  (declared, no longer a DIM); same rationale as `PostLogoutRedirectUris`. Material changes:
  - §1: replaced `IClientSecretVerifier? SecretVerifier` with `IClientSecret? ClientSecret`;
    promoted `IsPublic` from DIM to declared property. Updated XML docs referencing the
    extension point (`IClientSecretVerifier` → `IClientSecretHasher`).
  - §1a / `TokenEndpointAuthMethods` XML doc: updated all references from
    `IClientSecretVerifier` to `IClientSecretHasher` (paired with `IClientSecret`
    sub-interfaces) as the public extension point.
  - §2: replaced `SecretVerifier` init property and `IsPublicClient` derived getter with
    `IClientSecret? ClientSecret` init property and `required bool IsPublic` init property.
    Updated default-initializer XML doc to reference `ClientSecret is null` instead of
    `SecretVerifier` is `null`.
  - §3: complete rewrite around the data-vs-behaviour split. New subsections §3.1
    (`IClientSecret` hierarchy), §3.2 (`IClientSecretHasher` + generic base), §3.3
    (`Pbkdf2ClientSecretHasher` with PBKDF2-HMAC-SHA256, 600k default / 100k min iterations,
    16-byte salt, 32-byte hash, explicit empty-input rejection), §3.4
    (`CompositeClientSecretHasher` — internal, concrete-type-registered, dispatch via
    `CanHandle` first-match-wins, `PadTiming()` on every failure path), §3.5
    (`AddSecretsHasher<T>(isDefault)` extension + framework auto-registration of the default
    `Pbkdf2ClientSecretHasher`), §3.6 (startup resolution rules with the exact exception
    wording), §3.7 (ORM friendliness), §3.8 (public-vs-confidential distinction now driven
    by `IsPublic` + `ClientSecret` consistency, no separate types).
  - §3b: rewrote the "Timing padding for fast hashers" paragraph to reference
    `CompositeClientSecretHasher.PadTiming()` and the precomputed dummy
    secret/presented-plaintext built at composite startup (replacing the deleted
    `PlaintextClientSecretVerifier`/`Pbkdf2ClientSecretVerifier` distinction).
  - §6 `ValidateClient`: simplified — the `IsPublic` ⇔ `ClientSecret is null` ⇔
    `AllowedTokenEndpointAuthMethods == { None }` consistency check is now purely local.
    `InMemoryClientRepository` constructor now takes `CompositeClientSecretHasher` to power
    the per-client empty-string defence-in-depth check; per-hasher empty-string rejection
    is enforced inside each framework hasher (e.g.
    `Pbkdf2ClientSecretHasher.VerifyCore` returns `false` for empty presented input).
    Removed the `PlaintextClientSecretVerifier` advisory warning (the type no longer exists).
    Updated per-value auth-method advisory `LogWarning` text to reference
    `IClientSecretHasher`.
  - §7: rewrote DI sample — `var hasher = new Pbkdf2ClientSecretHasher();` shown at the top;
    `CreateConfidential` factory now takes `hasher: IClientSecretHasher` as its first
    parameter and calls `hasher.Create(plaintext)` internally; `CreatePublic` unchanged in
    parameters. Added "production: pre-hashed credential" example using the record
    initializer with a direct `Pbkdf2ClientSecret(...)` (no hasher needed at registration
    time). Added an EF entity sketch (`ClientEntity : IClientRegistration` with flat
    `Pbkdf2Iterations`/`Pbkdf2Salt`/`Pbkdf2Hash` columns and a `[NotMapped]` projection)
    framed as one of multiple paths (bcrypt / argon2id follow the same pattern). Updated
    `AddInMemoryClients` factory to inject `CompositeClientSecretHasher` into
    `InMemoryClientRepository`.
  - §8: removed verifier-related rows; added rows for the `IsPublic` ⇔ `ClientSecret` ⇔
    `AllowedTokenEndpointAuthMethods` consistency check, the per-hasher empty-string defence
    (composite-level and `Pbkdf2ClientSecretHasher`-level), the whole-set
    `AllowedTokenEndpointAuthMethods` recognition rule, and the hasher-resolution startup
    validation (with pointer to the §3.6 resolution table). Updated request-time bullet to
    reference `CompositeClientSecretHasher.Verify` and `PadTiming()`.
  - Rejected Alternatives: kept the original `string? ClientSecret` entry (now framed as
    the *earliest* draft) and added two new entries — "Embedding `IClientSecretVerifier`
    (or any service) on `IClientRegistration`" (rejected because it conflated data and
    behaviour, was ORM-hostile, and forced entities to carry behavioural services) and
    "A single `string Algorithm` discriminator on `IClientSecret` with switch-based
    dispatch" (rejected in favour of the marker hierarchy because algorithm parameter
    shapes differ and switch-based dispatch is an abstraction leak). Updated
    "Separate types for public and confidential clients" prose to refer to `IsPublic`
    rather than the now-deleted derived `IsPublicClient`. Updated "Strings for all
    per-client protocol vocabularies" and "Closed enums" entries to reference
    `IClientSecretHasher` instead of `IClientSecretVerifier`.
  - Consequences (Positive): replaced verifier-centric bullets with the new bullets on
    data-vs-behaviour split (registration data is pure data, ORM-friendly), pluggable
    hasher extensibility, switch-free verification path, and the
    `CompositeClientSecretHasher.PadTiming()` defence. Kept all redirect-URI / scope /
    repository / signing-algorithms bullets unchanged.
  - Consequences (Negative): removed the now-obsolete `PlaintextClientSecretVerifier`
    bullet and the `IClientSecretVerifier`-indirection bullet. Added bullets on the cost
    of implementing a new hasher (four small types, mitigated by `ClientSecretHasher<T>`),
    the strict startup-validation behaviour for ambiguous hasher resolution, the
    concrete-type registration requirement for `CompositeClientSecretHasher` (with the
    self-injection explanation), and the source-breaking nature of the
    `SecretVerifier` → `ClientSecret`/`IClientSecretHasher` shift (acceptable while
    Draft). Added a bullet on the `CreateConfidential(hasher: …)` parameter and why a
    hidden default was rejected. Added a bullet on the `IsPublic` DIM → declared
    promotion, mirroring the `PostLogoutRedirectUris` justification.
  - Package ownership table: replaced `IClientSecretVerifier` /
    `PlaintextClientSecretVerifier` / `Pbkdf2ClientSecretVerifier` rows with rows for
    `IClientSecret` / `IPbkdf2ClientSecret` / `Pbkdf2ClientSecret`,
    `IClientSecretHasher` / `ClientSecretHasher<TSecret>` / `Pbkdf2ClientSecretHasher`,
    and `CompositeClientSecretHasher` / `ClientSecretHasherOptions` /
    `ClientSecretHasherOptionsValidator`. Added `AddSecretsHasher<T>` to the
    `ZeeKayDa.Auth.AspNetCore` extensions row.
  - D2 documentation requirement rewritten around ORM mapping of `IPbkdf2ClientSecret`
    (EF Core / NHibernate / Dapper) plus a "how to implement a new hasher" guide. D3
    generalised from `PlaintextClientSecretVerifier` to "any sample using a plaintext
    secret literal". D1, D4, D5, D6, D7 unchanged.
  - Spec References: unchanged — the security primitives used (PBKDF2,
    `CryptographicOperations.FixedTimeEquals`, `RandomNumberGenerator`) are .NET BCL,
    not protocol specs, and the protocol-level surface introduced by this revision is
    purely internal.

