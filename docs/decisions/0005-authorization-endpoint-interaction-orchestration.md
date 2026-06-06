# ADR 0005 — Authorization Endpoint Interaction Orchestration

**Status:** Proposed  
**Date:** 2026-07-01

---

## Context

The authorization endpoint (`/connect/authorize`) is the entry point of every OAuth 2.x / OIDC
flow. Its implementation requires answering a set of questions that span multiple packages,
multiple spec documents, and the boundary between framework responsibility and host-application
responsibility:

1. **Who owns the protocol state machine?**  
   The authorization request must be validated, the interactive steps (authentication, consent,
   provider selection) must be sequenced, and a well-formed authorization response must eventually
   be issued to the relying party. Something must own that sequence and guarantee it cannot be
   bypassed or interrupted without a correct error response.

2. **Who owns the actual authentication mechanics?**  
   Credential validation (username/password), external provider callbacks (OAuth2, OIDC,
   BankID), session cookies — these are already solved problems in ASP.NET Core. Reimplementing
   them inside ZeeKayDa.Auth would produce an inferior alternative with a smaller ecosystem.

3. **How does a host application wire its own login page, consent page, and provider-selection
   page into the flow?**  
   The framework cannot own these pages — the host application owns the UI, the branding, and
   often the user model. The framework must define a narrow, well-typed interaction surface that
   lets host code participate in the flow without the framework ever taking a hard dependency on
   how that participation is implemented.

4. **How is the half-authenticated state managed during multi-step interactions?**  
   Between the external provider callback (or "collect more info" redirect) and the eventual
   code issuance, the framework holds a principal that is not yet promoted to the session. This
   state must be stored somewhere, must expire, and must be protected against replay and
   cross-flow misuse.

5. **How are per-scheme callbacks registered cleanly without coupling callback path design to a
   particular provider ecosystem?**

The authorization endpoint epic addresses all five questions. This ADR captures the settled
architectural decisions for each.

---

## Decision

### 1. Hybrid ownership model

ZeeKayDa.Auth and ASP.NET Core have strictly delimited responsibilities:

| Concern | Owner |
|---|---|
| Authorization request validation (params, PKCE, redirect URI) | ZeeKayDa.Auth |
| Interaction context lifecycle (creation, resumption, expiry) | ZeeKayDa.Auth |
| Interaction context cookie | ZeeKayDa.Auth (registered by `AddZeeKayDaAuth`) |
| SSO session (principal promotion after successful sign-in) | ZeeKayDa.Auth |
| Authorization code issuance and redirect to client | ZeeKayDa.Auth |
| Sequencing interactive steps (authenticate → consent → issue) | ZeeKayDa.Auth |
| Credential validation (username/password) | Host application |
| Login / consent / provider-selection UI | Host application |
| External provider OAuth2/OIDC mechanics | `Microsoft.AspNetCore.Authentication.*` |
| Cookie and session management for external handler callbacks | ASP.NET Core |

ZeeKayDa.Auth owns the protocol state machine and the interaction context. ASP.NET Core's
authentication infrastructure owns the mechanics of each interactive step. These two halves
communicate through interaction service interfaces (see §4) that the host application calls from
its own endpoints.

### 2. `IAuthenticationRequestHandler` as the `/connect/authorize` interceptor

`/connect/authorize` is handled by registering ZeeKayDa.Auth's authorization endpoint handler
as an `IAuthenticationRequestHandler` in the `UseAuthentication()` middleware. The handler
intercepts requests matching `/connect/authorize` (and per-scheme callback paths, see §3) before
any downstream route is consulted.

```csharp
// DI — ZeeKayDa.Auth.AspNetCore
services.AddAuthentication()
        .AddScheme<ZeeKayDaAuthHandlerOptions, ZeeKayDaAuthHandler>(
            ZeeKayDaAuthDefaults.AuthenticationScheme, _ => { });
```

`MapZeeKayDaAuth()` is not required when `IAuthenticationRequestHandler` handles all protocol
endpoints. Protocol-adjacent endpoints (JWKS, discovery) are registered via an endpoint data
source contributed directly inside `AddZeeKayDaAuth()`. `MapZeeKayDaAuth()` will be introduced
only if a concrete need arises later (see resolved Open Question §A).

A future optional UI package (`ZeeKayDa.Auth.AspNetCore.UI`) is explicitly out of scope for
this ADR. Its delivery mechanism — whether a custom endpoint data source, embedded Razor Pages,
or something else — is an open question deferred to that package's own design (see Open
Question §D).

**Why `IAuthenticationRequestHandler`, not a minimal API route?**  
`/connect/authorize` must handle `GET` and `POST` (OIDC Core §3.1.2.1 allows both). More
importantly, the authorization endpoint must be capable of **short-circuiting the pipeline** —
issuing challenge/redirect responses without allowing downstream middleware to see the request.
`IAuthenticationRequestHandler.HandleRequestAsync` returns `true` when the request has been
fully handled, preventing any further pipeline execution. A minimal API route cannot prevent
downstream middleware from observing the request, and the ordering constraints around
`UseAuthentication` are more predictable when ZeeKayDa.Auth participates as an authentication
handler rather than a route.

### 3. Per-scheme callback endpoints at `/connect/callback/{scheme}`

ZeeKayDa.Auth registers one callback path per external provider scheme:

```
/connect/callback/facebook
/connect/callback/bankid
/connect/callback/google
```

These paths are intercepted by the same `IAuthenticationRequestHandler` described in §2. The
handler calls `HttpContext.AuthenticateAsync(scheme)` to trigger the external handler's callback
logic, then fires the `OnProviderSignIn` event (see §5) with the resulting external principal.

**Rejected alternative — generic `/connect/provider-callback?scheme=X`:**  
A single path with a query-string discriminator was considered. It was rejected because:
(a) per-scheme paths produce clear, auditable log entries and browser developer tool entries;
(b) scheme names are known at startup — there is no reason to defer path uniqueness to a
query-string at runtime;
(c) a generic path would require the handler to trust a user-supplied `scheme` query parameter
for scheme dispatch — a query parameter that is present on the incoming request and visible to
anyone who can inspect network traffic. Per-scheme paths encode the scheme in the route template,
which is resolved by the ASP.NET Core router before the handler runs, not from arbitrary
request input.

### 4. DI registration API

```csharp
builder.Services
    .AddZeeKayDaAuth(o =>
    {
        o.Issuer = "https://id.example.com";

        // Interaction routing — paths that ZeeKayDa redirects to during the flow
        o.AuthorizationEndpoint.Interaction.AutoChallengeSingleProvider = true;
        o.AuthorizationEndpoint.Interaction.SelectProviderPath = "/signin/providers";
        o.AuthorizationEndpoint.Interaction.ConsentPath = "/consent";
        o.AuthorizationEndpoint.Interaction.ErrorPath = "/error";

        // Fires for ALL sign-ins (local, external providers, custom). No interrupt capability.
        o.OnSigningIn = async ctx =>
        {
            // ctx.Principal, ctx.Scheme, ctx.InteractionContext
        };

        // Registers four internal cookie schemes:
        //   "zkd.session"     — SSO session (shared across all auth methods)
        //   "zkd.interaction" — interaction context storage (default; replaceable with IDistributedCache)
        //   "zkd.external"    — provider callback transport (seconds-lived)
        //   "zkd.pending"     — pending principal for collect-more-info flows (minutes-lived)
    })
    .WithLocalAuth(o =>
    {
        // Local auth: host app owns credential validation entirely.
        // ZeeKayDa provides the interaction handoff mechanism (IAuthenticationInteraction),
        // not the credential validation logic.
        o.LoginPath = "/auth/login";
    })
    .WithProviders(
        auth =>
        {
            // auth is IAuthenticationBuilder — any ASP.NET Core auth handler works here.
            auth.AddFacebook(o => { /* standard Facebook options */ });
            auth.AddBankId(o => { /* ActiveLogin BankID — same pattern */ });
        },
        o =>
        {
            // Global OnProviderSignIn — fires for every scheme unless per-scheme overrides.
            // Default (no call made): auto-promotes principal, issues code.
            o.OnProviderSignIn = async ctx =>
            {
                // Explicit interrupts only:
                await ctx.RedirectToAsync("/collect-more");
                // — or —
                await ctx.DenyAsync("account_disabled");
            };

            // Per-scheme override — replaces global for this scheme only.
            o.ForScheme("facebook", scheme =>
            {
                scheme.PostSignInPath = "/auth/complete-facebook";
                // — or —
                // scheme.OnProviderSignIn = async ctx => { ... };
            });
        });
```

**Session and interaction cookies are registered by `AddZeeKayDaAuth`, not by `WithLocalAuth`.**
Both local auth and external providers share the same SSO session. Splitting cookie registration
across builder methods would create an ordering hazard (calling `WithProviders` without
`WithLocalAuth` would silently omit the session cookie) and would misrepresent the SSO cookie as
a local-auth concern rather than a framework-wide one.

**`WithProviders` forces `SignInScheme = "zkd.external"` on all registered remote handlers.**
The `auth` parameter passed to the `WithProviders` delegate is a ZeeKayDa wrapper around
`AuthenticationBuilder`. It intercepts every `AddScheme<TOptions, THandler>()` call and, if
`TOptions` derives from `RemoteAuthenticationOptions`, registers a typed
`IPostConfigureOptions<TOptions>` that forces `SignInScheme = "zkd.external"` for that scheme
(see §6 for why this scheme exists).
This runs after all developer-supplied configuration so it cannot be accidentally overridden.
Handlers whose options do not derive from `RemoteAuthenticationOptions` are unaffected and the
developer is responsible for any `SignInScheme` wiring they require — in practice, all OAuth,
OIDC, and social login handlers in the ASP.NET Core ecosystem derive from
`RemoteAuthenticationOptions`.

### 5. `OnProviderSignIn` event model — implicit proceed, explicit interrupts only

After receiving an external principal from any provider callback, ZeeKayDa fires the
`OnProviderSignIn` event. The model mirrors the ASP.NET Core authentication events pattern
(`OnCreatingTicket`, `OnTokenValidated`, etc.), which is already familiar to consumers:

- **If no interrupt is called**: ZeeKayDa promotes the principal to the session and issues the
  authorization code. No explicit "proceed" call is required.
- **`ctx.RedirectToAsync(path)`**: ZeeKayDa stores the pending principal (see §6) and redirects
  the browser to `path`. The flow resumes when the host app calls `interaction.SignInAsync`.
- **`ctx.DenyAsync(error)`**: ZeeKayDa redirects to the relying party's redirect URI with the
  given OAuth error code.

This model keeps the happy path minimal — a consumer who does not need to intercept provider
sign-in writes no event handler at all.

### 5a. `OnSigningIn` — universal sign-in hook (all authentication methods)

`OnSigningIn` fires for **all** sign-ins — local auth, external providers, and any custom
authentication flow — immediately before code issuance and SSO session promotion.

**Intended use:** cross-cutting claims enrichment (adding tenant ID, roles from a database,
audit logging, etc.) that applies regardless of how the user authenticated.

**No interrupt capability.** `ctx.RedirectToAsync` and `ctx.DenyAsync` are not available on the
`OnSigningIn` context. The user is already fully authenticated at this point; the hook is
informational and additive only. If an interrupt is needed:
- For external providers — use `OnProviderSignIn` (see §5).
- For local auth or custom flows — handle the interrupt before calling `SignInAsync`.

`ctx.Scheme` identifies the authentication method used (`"local"`, `"facebook"`, `"bankid"`,
etc.), enabling scheme-specific branching within a single handler.

```csharp
// Configured on AddZeeKayDaAuth options (fires for all methods):
o.OnSigningIn = async ctx =>
{
    // ctx.Principal, ctx.Scheme, ctx.InteractionContext
    ctx.Principal.AddClaim("tenant", await ResolveTenantAsync(ctx.Principal));
    // No interrupt capability — flow always proceeds after this event.
};
```

**Comparison with `OnProviderSignIn`:**

| Event | Fires for | Can interrupt? | Purpose |
|---|---|---|---|
| `OnProviderSignIn` | External providers only | Yes (`RedirectToAsync`, `DenyAsync`) | Provider-specific enrichment; collect extra data |
| `OnSigningIn` | All sign-ins | No | Cross-cutting claims enrichment; audit |

### 6. Pending principal: named cookie authentication scheme (`"zkd.pending"`)

When `OnProviderSignIn` calls `ctx.RedirectToAsync(...)`, the external principal cannot yet be
promoted to the session (consent may not have been collected; additional claims may be needed).
ZeeKayDa stores this half-authenticated principal using a **named ASP.NET Core cookie
authentication scheme** registered internally as `"zkd.pending"` via
`AddCookie("zkd.pending", ...)`. This scheme is registered by ZeeKayDa at startup; the developer
never sees or configures it directly.

Using ASP.NET Core's `AddCookie` provides the full security property set for free: Data Protection
encryption and signing, `HttpOnly`, `Secure`, `SameSite=Lax`, and configurable TTL — no custom
cookie-writing code is needed inside ZeeKayDa.

Key properties of this scheme:

- **Named scheme — internal to ZeeKayDa**: the scheme name `"zkd.pending"` is an internal
  ZeeKayDa detail. The host app sees only the typed `PendingPrincipal` value returned by
  `interaction.GetPendingPrincipalAsync()`.
- **`zkd:interaction_id` claim binds the pending principal to the interaction context**: a
  `zkd:interaction_id` claim is appended to the pending principal before signing in to
  `"zkd.pending"`. On `SignInAsync`, ZeeKayDa authenticates `"zkd.pending"`, verifies the
  claim matches the current interaction context ID, and rejects the principal if it does not.
  This prevents a pending principal from one flow from being used to complete a different flow.
- **`SlidingExpiration = false` — hard TTL, not sliding**: the TTL window must not reset on page
  reload or cookie re-read. Sliding expiration would allow an adversary who can keep the cookie
  alive (e.g. by repeatedly loading a page) to extend the window indefinitely.
- **Single-use**: `SignInAsync` calls `HttpContext.SignOutAsync("zkd.pending")` immediately
  after authenticating the pending principal, before promoting to the session. Re-calling
  `SignInAsync` (or replaying the response) finds no `"zkd.pending"` cookie and returns an
  error.
- **Default TTL: 15 minutes (configurable)**. This must be configured to be shorter than the
  interaction context TTL (see Security Considerations — interaction context defaults to 30
  minutes). An interaction context may survive while the user is filling in a form; a pending
  (half-authenticated) principal should expire sooner.

**Implementation sketch (ZeeKayDa internals — not host app code):**

```csharp
// Storing pending principal (inside ZeeKayDa, after OnProviderSignIn redirect)
var pendingIdentity = new ClaimsIdentity(
    externalPrincipal.Claims.Append(new Claim("zkd:interaction_id", interactionId)),
    "zkd.pending");
await http.SignInAsync("zkd.pending", new ClaimsPrincipal(pendingIdentity));

// Consuming pending principal (inside SignInAsync)
var result = await http.AuthenticateAsync("zkd.pending");
if (!result.Succeeded) → handle as timeout (see §10)
var boundId = result.Principal.FindFirst("zkd:interaction_id")?.Value;
if (boundId != currentInteractionId) → reject
await http.SignOutAsync("zkd.pending"); // single-use
// promote, issue code, redirect
```

The following edge cases are explicitly designed for:

| Scenario | Behaviour |
|---|---|
| User abandons mid-collection | New `/authorize` request creates a new interaction context; old `"zkd.pending"` cookie is orphaned and expires naturally |
| Replay of pending cookie | Cookie is consumed (signed out) on `SignInAsync`; replay finds no `"zkd.pending"` session and is rejected |
| `RedirectToAsync` called, `SignInAsync` never called | Both interaction context and pending cookie expire; timeout handling per §10 applies |
| Multiple browser tabs | Two independent interaction contexts, two independent `"zkd.pending"` cookies — both valid concurrently |
| Pending TTL expires before `SignInAsync` | `AuthenticateAsync("zkd.pending")` fails; timeout handling per §10 applies |

**Why a named cookie scheme, not custom cookie writing?**  
Using `AddCookie("zkd.pending", ...)` reuses ASP.NET Core's battle-tested cookie security
implementation (Data Protection, HttpOnly, Secure, SameSite) and avoids reinventing it inside
ZeeKayDa. The security properties are centrally controlled by the options object ZeeKayDa
registers — not scattered across bespoke cookie-writing code paths.

**Why a cookie, not the interaction store?**  
The interaction store is the host application's storage concern — the host plugs in a store
implementation. Placing the pending principal in the interaction store would leak a security-
sensitive object (an unauthenticated, external-provider-sourced principal) into host-controlled
storage whose implementation ZeeKayDa cannot audit. An internal, named-scheme cookie keeps this
sensitive state under ZeeKayDa's control and requires no I/O beyond cookie parsing.

**Why two internal cookie schemes (`zkd.external` and `zkd.pending`) rather than one?**

ZeeKayDa uses two distinct internal cookie schemes for the external-provider flow. Neither is
visible to the host application.

**`zkd.external` — provider callback transport (seconds-lived)**

- Registered internally; the developer never sees or configures this scheme.
- `SignInScheme` is forced to `"zkd.external"` on all `RemoteAuthenticationOptions`-derived
  handlers (see §4 `WithProviders` `SignInScheme` forcing).
- Exists only for the duration between the external handler's callback (e.g. `/signin-facebook`)
  and ZeeKayDa's `/connect/callback/{scheme}` processing it — typically milliseconds.
- Contains **no** `zkd:interaction_id` binding claim — the external handler has no knowledge of
  the ZeeKayDa interaction context; it signs into `"zkd.external"` before ZeeKayDa has had a
  chance to add any binding.
- ZeeKayDa calls `SignOutAsync("zkd.external")` immediately at `/connect/callback/{scheme}`
  after reading the principal.

**`zkd.pending` — developer-facing pending state (minutes-lived)**

- Created **only** when `ctx.RedirectToAsync(...)` is called inside `OnProviderSignIn`.
- ZeeKayDa appends the `zkd:interaction_id` binding claim before signing into `"zkd.pending"`.
  This claim is what enables cross-flow misbinding protection (see §6 above).
- Has a configurable TTL (default 15 minutes; must be shorter than the interaction context TTL).
- `SlidingExpiration = false` — hard TTL; the window does not reset on page reload or cookie
  re-read.

**Why not merge them into one scheme?**

- The external handler signs into its scheme *before* ZeeKayDa has had a chance to add
  `zkd:interaction_id`. Merging would require ZeeKayDa to sign out and immediately re-issue the
  same cookie at the callback solely to inject the binding claim — awkward and unnecessary.
- In the happy path (no `ctx.RedirectToAsync` call), `zkd.pending` is **never created** —
  `zkd.external` is read and immediately discarded. Merging would force the binding-claim logic
  into the common path.
- The semantic distinction is intentional: `zkd.external` = *"just arrived from provider,
  unprocessed"*; `zkd.pending` = *"deliberately held for developer to act on"*.

### 6b. Authorization interaction context storage

The authorization interaction context (validated request parameters: `client_id`, validated
`redirect_uri`, `scope`, `state`, `nonce`, `code_challenge`, expiry) must be stored securely for
the duration of the login flow. ZeeKayDa provides two built-in storage strategies and does not
define a ZeeKayDa-specific `IAuthorizationInteractionStore` interface — the standard .NET
`IDistributedCache` abstraction already serves that role.

**Guiding principle: do not create a ZeeKayDa abstraction when a standard .NET abstraction already
exists for the same purpose.**

#### Default: encrypted cookie (self-contained, zero config)

ZeeKayDa registers an internal named cookie scheme `"zkd.interaction"` via
`AddCookie("zkd.interaction", ...)`. The interaction context is serialized and stored in the
cookie using ASP.NET Core Data Protection (AES-256 + HMAC), identical to how cookie
authentication tickets work.

Properties:
- `HttpOnly = true`, `Secure = true`, `SameSite = Lax`
- `SlidingExpiration = false` — hard TTL, default 30 minutes (configurable)
- No server-side state — scales trivially across instances without shared storage (Data Protection
  key ring required for multi-instance)
- Size: interaction context contains ~300–500 bytes of raw data; encrypted + base64 ≈ 1KB —
  comfortably within the 4096-byte per-cookie browser limit

#### Upgrade: `IDistributedCache`-backed storage

For cases where cookie size is a concern or server-side revocation is needed, ZeeKayDa can store
contexts in any `IDistributedCache` implementation. The cookie then contains only an opaque
handle (≈50 bytes).

```csharp
// Simple: use the app's existing IDistributedCache registration
builder.Services
    .AddZeeKayDaAuth(o => { ... })
    .UseDistributedCacheInteractionStore();

// Isolated: use a dedicated, keyed IDistributedCache instance (.NET 8+)
// This avoids sharing cache infrastructure with the app's own session/output-cache usage.
builder.Services.AddKeyedStackExchangeRedisCache("zkd.interactions", o =>
{
    o.Configuration = "redis:6379";
    o.InstanceName = "zkd:";
});

builder.Services
    .AddZeeKayDaAuth(o => { ... })
    .UseDistributedCacheInteractionStore(serviceKey: "zkd.interactions");
```

When `serviceKey` is supplied, ZeeKayDa resolves the cache via `IKeyedServiceProvider`. When
omitted, it resolves the default unkeyed `IDistributedCache`. Requires .NET 8+ (keyed services).

#### Why not a ZeeKayDa-specific `IAuthorizationInteractionStore`?

The realistic upgrade scenarios are covered by `IDistributedCache`:
- Redis — `AddStackExchangeRedisCache`
- SQL Server — `AddSqlServerCache`
- Custom backend — implement `IDistributedCache`

If a genuinely compelling case for a ZeeKayDa-specific interface emerges (e.g. custom revocation
semantics not expressible through cache key removal), it can be added in a future version without
breaking the existing API.

### 7. Interaction service interfaces

The host application participates in the flow through two purpose-scoped interaction interfaces,
all in `ZeeKayDa.Auth.AspNetCore`.

> **Note:** `ZeeKayDaInteractionException` (referenced in the error contracts below) is a
> ZeeKayDa-specific exception type. Its full definition — including inheritance, message
> conventions, and any `Data` properties — is deferred to the exception design ADR (tracked in
> a separate issue).

```csharp
// Single interface for all developer-controlled authentication completion.
// Registered by WithLocalAuth; scoped to the current HTTP request via IHttpContextAccessor.
// All terminal methods write the redirect response — callers must not write to the response afterwards.
public interface IAuthenticationInteraction
{
    /// <summary>
    /// Promotes the supplied principal to the ZeeKayDa SSO session and completes the
    /// authorization flow — redirecting the browser to the relying party's redirect URI
    /// with the issued authorization code.
    /// </summary>
    /// <remarks>
    /// Works for all authentication paths: local auth, magic links, OTP, and
    /// collect-more-info completion after an external provider callback.
    /// If a pending principal cookie (<c>zkd.pending</c>) is present and bound to the
    /// current interaction context, it is automatically consumed before sign-in completes.
    /// This ensures the pending cookie is always cleaned up regardless of how the flow ends.
    /// Terminal — writes the redirect response. Callers must not write to the response after this call.
    /// Throws <see cref="ZeeKayDaInteractionException"/> if no active authorization interaction
    /// context is found.
    /// </remarks>
    Task SignInAsync(ClaimsPrincipal principal, string amr);

    /// <summary>
    /// Returns the pending external principal stored during the <c>OnProviderSignIn</c> event
    /// when <c>ctx.RedirectToAsync</c> was called.
    /// Returns <see langword="null"/> if the pending cookie is absent, expired, or misbound
    /// to a different interaction context — callers should treat null as a recoverable error
    /// (e.g. redirect back to the start of the flow).
    /// </summary>
    /// <remarks>
    /// Only needed when enrichment of the external principal is required before sign-in.
    /// If no enrichment is needed, the <c>OnProviderSignIn</c> event (no interrupt) or
    /// <c>OnSigningIn</c> are the appropriate extension points.
    /// </remarks>
    Task<PendingPrincipal?> GetPendingPrincipalAsync();
}

public sealed class PendingPrincipal
{
    public required ClaimsPrincipal Principal { get; init; }

    /// <summary>The authentication scheme that produced this principal (e.g. "facebook", "bankid").</summary>
    public required string Scheme { get; init; }
}
```

> `CompleteAsync` was considered as a separate method for the collect-more-info completion path. It was removed because the distinction between `SignInAsync` and `CompleteAsync` imposed unnecessary cognitive load — a developer in a collect-more-info endpoint had no obvious reason to prefer one over the other. `SignInAsync` is unified: it checks for and consumes any pending cookie automatically, so the developer always calls the same method regardless of how the flow arrived at this point.

**Error contract:**

| Method | Failure condition | Behaviour |
|---|---|---|
| `SignInAsync` | No active interaction context | `ZeeKayDaInteractionException`: "No active ZeeKayDa authorization interaction found. Ensure this endpoint is only reached via a ZeeKayDa-orchestrated authorization flow." |
| `GetPendingPrincipalAsync` | No pending principal, expired, or misbound | Returns `null` — recoverable; caller redirects to error or restarts flow |

```csharp
// Used in the host's consent endpoint (GET/POST /consent).
public interface IConsentInteraction
{
    /// <summary>Returns the authorization request details for rendering the consent UI.</summary>
    Task<ConsentRequest> GetRequestAsync();

    /// <summary>Records granted scopes and completes the authorization flow.</summary>
    /// <remarks>Terminal — writes the redirect response.</remarks>
    Task GrantAsync(IEnumerable<string> grantedScopes);

    /// <summary>
    /// Rejects consent and redirects the browser to the relying party's redirect URI
    /// with <c>error=access_denied</c>.
    /// </summary>
    /// <remarks>Terminal — writes the redirect response.</remarks>
    Task DenyAsync();
}
```

**Terminal methods write the redirect response and must be the last operation on the response.**
This is the same contract as `HttpContext.SignInAsync` and `HttpContext.ChallengeAsync` in
ASP.NET Core — consumers familiar with those patterns will find the model unsurprising.

### 8. Host application pipeline and endpoint wiring

```csharp
// Middleware pipeline
app.UseAuthentication(); // ZeeKayDa intercepts /connect/authorize and /connect/callback/{scheme}
app.UseAuthorization();

// Note: app.MapZeeKayDaAuth() is NOT required. Protocol endpoints (discovery, JWKS) are
// registered via endpoint data sources inside AddZeeKayDaAuth(). See resolved Open Question §A.

// Host application interaction endpoints — completely host-owned
app.MapPost("/auth/login", LoginPost);
app.MapGet("/consent", ConsentPage);
app.MapPost("/consent", ConsentPost);
app.MapGet("/signin/providers", ProviderSelectionPage);
app.MapGet("/auth/complete-facebook", CollectProfilePage);
app.MapPost("/auth/complete-facebook", CollectProfilePost);
```

**ZeeKayDa does not own or render any of the interaction pages.** The `LoginPath`,
`ConsentPath`, `SelectProviderPath`, and `ErrorPath` values in options are only redirect targets
— ZeeKayDa sends the browser to them but does not control what they render. This is an explicit
design constraint: the framework is responsible for the protocol, not the UX. A future optional
UI package (`ZeeKayDa.Auth.AspNetCore.UI`) could provide default pages; its delivery mechanism
is deferred to that package's own design — see Open Question §D.

### 9. Representative host endpoint implementations

The following pseudocode illustrates the expected host endpoint patterns. These are not framework
code; they are the developer experience the framework's interaction interfaces are designed to
enable.

**Local auth sign-in** — developer owns credential validation entirely:

```csharp
static async Task LoginPost(
    IAuthenticationInteraction interaction,
    IMyUserService users,   // developer's own abstraction — ZeeKayDa never references it
    string username,
    string password)
{
    var user = await users.ValidateAsync(username, password);
    if (user is null)
    {
        // Interaction context cookie still alive — flow resumes on retry.
        return Results.Redirect("/auth/login?error=invalid");
    }
    await interaction.SignInAsync(user.ToClaimsPrincipal(), "pwd");
    // Terminal — ZeeKayDa has written the redirect to the response. No return needed.
}
```

**Provider "collect more info"** — after `OnProviderSignIn` calls `ctx.RedirectToAsync`:

```csharp
// POST /auth/complete-facebook — collect extra data, then complete sign-in
static async Task CollectProfilePost(
    IAuthenticationInteraction interaction,
    string email)
{
    var pending = await interaction.GetPendingPrincipalAsync();
    if (pending is null)
    {
        // Pending session expired or was consumed — restart the flow
        Results.Redirect("/error");
        return;
    }

    // Enrich the external principal with collected data
    pending.Principal.AddClaim(new Claim("email", email));

    // Same call as local auth — SignInAsync handles both cases
    await interaction.SignInAsync(pending.Principal, pending.Scheme); // "facebook", "bankid", etc.
}
```

**Consent:**

```csharp
static async Task ConsentPost(
    IConsentInteraction interaction,
    ConsentDecision decision)
{
    if (decision.Denied)
    {
        await interaction.DenyAsync();
        return;
    }
    await interaction.GrantAsync(decision.GrantedScopes);
    // Terminal.
}
```

### 10. Timeout handling

ZeeKayDa must **never redirect to a URI that was not validated and stored in the interaction
context.** Redirecting to an unvalidated URI — even one supplied in a timed-out request — is an
open redirect vulnerability (RFC 6749 §3.1.2.3). If the interaction context is gone and the
`redirect_uri` cannot be recovered, the error page is the only safe response.

The following table defines the response strategy for each timeout scenario:

| Scenario | What expired | Response |
|---|---|---|
| Pending principal expired (user too slow on collect-info page) | `"zkd.pending"` cookie | Redirect to client: `error=login_required&zkd_error=timeout&state=...` |
| Interaction context expired (entire authorize session timed out) | interaction context | Redirect to client: `error=login_required&zkd_error=timeout&state=...` — only if `redirect_uri` is still recoverable from the context store |
| Both expired | both | Error page — no validated `redirect_uri` available; redirecting would be an open redirect vulnerability |

**Design rules:**

- **Do NOT restart the authorize flow automatically.** The relying party initiated the flow and
  is the correct party to decide whether to retry. Automatic restart would hide timeout events
  from the client and could mask underlying issues (e.g. misconfigured TTLs, browser re-opened
  after a long gap).
- **Do NOT show an error page when a validated `redirect_uri` is recoverable.** Redirecting the
  user back to the client with a structured error response is always the better user experience
  compared to a dead-end error page. The error page is reserved solely for the case where
  redirecting would be unsafe.
- **`zkd_error=timeout` is only sent to clients that opt into ZeeKayDa extensions.** See §11.

### 11. ZeeKayDa error extension parameter (`zkd_error`)

RFC 6749 does not prohibit additional parameters in authorization responses (RFC 6749 §8.5).
`zkd_error` is a ZeeKayDa-specific, opt-in extension that provides a machine-readable sub-code
alongside the standard `error` value.

**Core principles:**

- The `error` parameter **always** uses spec-defined values (RFC 6749 §4.1.2.1, OIDC Core
  §3.1.2.6) for interoperability with all relying parties regardless of opt-in status.
- `zkd_error` is the machine-readable sub-code for ZeeKayDa-aware clients only.
- `error_description` remains the human-readable extension point — free text, not for
  programmatic consumption by the client.
- `zkd_error` values **must not leak internal state** — they are coarse, client-actionable
  codes only (RFC 9700 information-disclosure caution).

**Opt-in per client:** `zkd_error` is only included in the response when the client
registration has `EnableZkdErrorCodes = true`. Clients that
have not opted in receive only the standard `error` and `error_description` parameters.

**Defined `zkd_error` values (starter set):**

| `error` | `zkd_error` | Meaning |
|---|---|---|
| `login_required` | `timeout` | Auth session or pending principal expired |
| `login_required` | `session_not_found` | Interaction context missing (e.g. browser cookie cleared) |
| `access_denied` | `consent_denied` | User explicitly denied consent |
| `access_denied` | `provider_denied` | External provider returned a denial |
| `server_error` | `internal` | Unhandled internal failure |

**Example response (opt-in client):**

```
redirect_uri?error=login_required
            &error_description=Authentication+session+expired
            &zkd_error=timeout
            &state=...
```

---

## Alternatives Considered

### A — ZeeKayDa owns the full interaction surface (no host endpoints)

The framework renders all interaction pages itself (login, consent, provider selection) using
embedded Razor views or minimal-API-based UI, and exposes only theming/configuration hooks.

**Rejected.** This is the "black box" model the framework explicitly rejects (see Design
Principle 1). It removes the host application's ability to integrate its own user model, its
own identity store, its own branding, and its own MFA flow. It also creates an implicit
dependency between ZeeKayDa and every UI technology the host might use. The interaction
service interface model (§7) achieves the same flow control with none of those constraints.
The option to ship optional default pages remains available as a separate, low-priority
package — it does not need to be built into the core path.

### B — Full delegation: ZeeKayDa issues challenges and lets ASP.NET Core handle everything

ZeeKayDa validates the authorization request and then issues a standard `ChallengeResult` via
`HttpContext.ChallengeAsync`. ASP.NET Core's cookie or external handler drives the user through
sign-in; ZeeKayDa picks up the resulting session cookie on the return visit and issues the code.

**Rejected.** This model breaks down as soon as the flow requires more than one interactive step.
Consent, provider selection, and post-provider principal enrichment all require ZeeKayDa to
maintain correlation between the original authorization request and the user's current browser
state. Without owning the interaction context, ZeeKayDa has no reliable way to know which
authorization request a returning authenticated user should be completing — especially under
concurrent tab use. The hybrid model (§1) is the minimum ownership footprint that keeps the
protocol state machine coherent without taking over the mechanics of each interactive step.

### C — `MapZeeKayDaAuth` only; no `IAuthenticationRequestHandler`

All ZeeKayDa endpoints, including `/connect/authorize`, are registered as minimal API routes via
`MapZeeKayDaAuth()`. No `IAuthenticationRequestHandler` is used.

**Rejected** (as the primary path, though it may co-exist for non-handler endpoints). The
authorization endpoint must be able to short-circuit the middleware pipeline — to respond with
a challenge or error without allowing downstream routes to observe the request. Minimal API
routes are downstream of the authentication middleware by design. An authorization endpoint
implemented as a minimal API route cannot suppress downstream middleware execution. More
critically, the challenge flow (`ChallengeAsync` to an external provider) and callback
interception (`/connect/callback/{scheme}`) fit naturally into the `IAuthenticationRequestHandler`
model, which is the established ASP.NET Core mechanism for this kind of pre-route interception.
`MapZeeKayDaAuth()` continues to serve routes that do not require pre-route interception.

### D — Generic callback path: `/connect/provider-callback?scheme={scheme}`

A single callback URL is registered for all external providers. The scheme name is read from
the `scheme` query parameter to dispatch to the correct external handler.

**Rejected** (see §3 for the full rationale). The key security concern is that a generic path
would require trusting the `scheme` query parameter — a value visible in browser history, server
logs, and referrer headers — to determine which authentication handler processes the callback.
An adversary who can manipulate the `scheme` parameter could potentially cause a callback
intended for one provider to be processed by another. Per-scheme paths encode the scheme in the
route template and are resolved by the router, not from request input.

---

## Consequences

### Positive

- **Protocol state machine cannot be bypassed.** ZeeKayDa owns the interaction context; the host
  application can only advance the flow through the typed interaction interfaces. A host endpoint
  that "forgets" to call `SignInAsync` simply leaves the interaction context
  alive until it expires — the flow stalls rather than producing an incorrect result.
- **Host application is unconstrained on UI and user model.** No ZeeKayDa type ever appears in
  the host's credential validation logic. `IMyUserService` is wholly the developer's design.
- **Familiar model for ASP.NET Core developers.** `IAuthenticationRequestHandler`, challenge/
  forbid semantics, external handler callback patterns, and event-based hooks (`OnCreatingTicket`
  family) are all patterns existing ASP.NET Core developers already know. ZeeKayDa layers its
  own protocol semantics on top of those patterns rather than replacing them.
- **No hidden state transitions.** Every state change in the interaction lifecycle (context
  created, pending principal stored, code issued) is triggered by an explicit call to an
  interaction interface method. There are no background timers, no automatic promotions on
  middleware re-entry, no implicit side-effects from reading a cookie.
- **Per-scheme callback paths are auditable.** Log correlation, browser devtools, and WAF rules
  can all target `/connect/callback/facebook` specifically rather than a generic path with a
  query discriminator.
- **Pending principal security properties** (short TTL, single-use, interaction binding) are
  enforced inside the framework and are not configurable to less-secure values without explicit
  opt-in.

### Negative / Trade-offs

- **More wiring for the host application.** The host must implement its own login page and wire
  `IAuthenticationInteraction.SignInAsync`. A framework that ships a default login page requires
  fewer lines of host code. This cost is accepted in exchange for not constraining the host's
  user model.
- **Terminal method contract requires discipline.** Methods such as `SignInAsync`,
  `GrantAsync`, and `DenyAsync` write to the HTTP response. Calling them and
  then continuing to write to the response is a programming error that will produce a corrupted
  response. The framework will throw `InvalidOperationException` if response writing is
  attempted after a terminal method has been called, but this is detectable only at runtime, not
  at compile time. XML documentation and integration test coverage are the primary mitigations.
- **`IAuthenticationRequestHandler` ordering is implicit.** `UseAuthentication()` must appear
  before `UseAuthorization()` and before any middleware that expects an authenticated identity.
  This is a standard ASP.NET Core constraint, not a ZeeKayDa-specific one, but it must be
  documented clearly because the authorization endpoint depends on it.
- **HTTPS enforcement moves into `HandleRequestAsync`.** Because `/connect/authorize` and
  `/connect/callback/{scheme}` are intercepted by `IAuthenticationRequestHandler` before routing
  fires, the endpoint group filters used for HTTPS enforcement and security headers (ADR 0004) do
  not apply. The handler performs the same checks directly: `Request.IsHttps` is tested at the
  top of `HandleRequestAsync`; security response headers are set on `Context.Response.Headers`
  before any response body is written. The logic and options (`AllowInsecureIssuer`, loopback
  check) are unchanged — only the interception point moves.
- **Reverse proxy / forwarded headers: `UseForwardedHeaders()` must precede `UseAuthentication()`.**
  `Request.IsHttps` is only correct when the host has configured forwarded-headers middleware
  (e.g. `app.UseForwardedHeaders()`, YARP, Azure App Service header forwarding) *before*
  `app.UseAuthentication()`. ZeeKayDa does not inspect `X-Forwarded-Proto` directly — doing so
  would bypass the host's trusted-proxy configuration and risk trusting spoofed headers. The
  correct deployment pattern is:
  ```csharp
  app.UseForwardedHeaders(); // must come first in reverse-proxy deployments
  app.UseAuthentication();   // ZeeKayDa sees correct Request.IsHttps
  ```
  This is standard ASP.NET Core guidance; ZeeKayDa's documentation must state it explicitly.
- **`"zkd.pending"` scheme requires shared Data Protection keys in multi-instance deployments.**
  If multiple server instances are deployed, the Data Protection keys used to sign/encrypt the
  `"zkd.pending"` cookie must be shared across instances (via `PersistKeysToAzureBlobStorage`,
  `PersistKeysToFileSystem`, etc.). This is a standard ASP.NET Core Data Protection constraint
  that also applies to the interaction context cookie and the SSO session cookie. ZeeKayDa must
  document it and must not attempt to solve distributed key management itself.

---

## Security Considerations

### CSRF / state parameter (RFC 6749 §10.12)

ZeeKayDa validates the `state` parameter on every authorization response. Relying parties are
expected to round-trip `state` as a CSRF token. ZeeKayDa's authorization request validation
enforces that `state` is present; dropping it is a discoverable misconfiguration.

### Open redirect prevention (RFC 6749 §3.1.2.3)

The `redirect_uri` in every authorization request is validated against the pre-registered set
for the client. No redirect is issued to an unregistered URI, regardless of what the request
presents. This is enforced in the authorization request validator before any interaction step
begins.

### PKCE mandatory (RFC 7636; RFC 9700 §2.1.1; OAuth 2.1 §4.1.1)

PKCE is mandatory for all client types. The authorization request validator rejects any request
that does not include `code_challenge` and `code_challenge_method=S256`. The `plain` method is
not implemented (see ADR 0003). The token endpoint validates `code_verifier` against the stored
`code_challenge` before issuing any token.

### Pending principal cookie security (`"zkd.pending"` scheme)

The pending principal is stored using the internally registered `"zkd.pending"` ASP.NET Core
cookie authentication scheme. All security properties come from `AddCookie` options:

- `HttpOnly` — inaccessible to JavaScript.
- `Secure` — sent only over HTTPS (consistent with the issuer HTTPS requirement from ADR 0001).
- `SameSite=Lax` — mitigates cross-site request forgery on the callback endpoint.
- Encrypted and signed using ASP.NET Core Data Protection — the cookie content is not readable
  or forgeable by the browser.
- `SlidingExpiration = false` — hard TTL; the window does not reset on page reload or cookie
  re-read, preventing an adversary from keeping the pending principal alive indefinitely.
- Bound to the current interaction context via the `zkd:interaction_id` claim — a pending
  principal from one authorization flow cannot be used to complete a different flow.
- Single-use — `SignOutAsync("zkd.pending")` is called by `SignInAsync` immediately after the
  principal is authenticated, before the SSO session is promoted.

### Interaction context cookie security

The interaction context cookie follows the same HttpOnly / Secure / SameSite=Lax / Data
Protection treatment as the pending principal cookie. Its TTL is configurable and defaults to
a value appropriate for an interactive sign-in session (suggested default: 30 minutes — longer
than the 15-minute pending principal default so that the invariant "pending TTL < interaction
TTL" holds with both defaults). It is separate from the SSO session cookie, which has a longer
lifetime.

### Per-scheme callback path and scheme name trust

The scheme name in `/connect/callback/{scheme}` is a route template value resolved by the ASP.NET
Core router. ZeeKayDa validates this value against the set of registered schemes at startup;
an unknown scheme name results in a 404 (not a dispatch to an unregistered handler). The scheme
name is never read from a user-supplied query parameter.

### Implicit flow / ROPC removed

The implicit flow (`response_type=token`) and the Resource Owner Password Credentials grant are
not implemented and will not be implemented. They are removed in OAuth 2.1 and deprecated by
RFC 9700. Any request presenting these response types or grant types is rejected with
`unsupported_response_type` or `unsupported_grant_type` respectively.

---

## Open Questions

These items are not resolved by this ADR and must be addressed before or during the epic
implementation.

### A — ~~Is `MapZeeKayDaAuth()` required when `IAuthenticationRequestHandler` is used?~~ ✅ Resolved

**Decision:** `MapZeeKayDaAuth()` is **not needed**. Protocol endpoints (JWKS, discovery) and
UI package endpoints are registered via endpoint data sources contributed inside
`AddZeeKayDaAuth()`. `MapZeeKayDaAuth()` will be introduced only if a concrete, future need
arises — it is not part of the current public API surface.

### B — ~~Does `WithLocalAuth` need to exist as a distinct builder method?~~ ✅ Resolved

**Decision:** `WithLocalAuth` stays as a separate builder method. Rationale:

- Keeps `LoginPath` off the common options class — it is not relevant to all deployments (a
  deployment using only external providers has no local login page).
- Provides a natural, isolated extension point for future local-auth-specific events (e.g.
  `OnBeforeLocalSignIn`, account lockout hooks) without polluting the shared options type.
- Is the natural registration site for a future default UI package
  (`ZeeKayDa.Auth.AspNetCore.UI`), which would contribute its default login page only when
  `WithLocalAuth` is called with the appropriate option.

### C — `MapZeeKayDaAuth()` vs `UseZeeKayDaAuth()` for non-route middleware concerns

ADR 0001 settled that `MapZeeKayDaAuth` is the correct name for route registration. However, if
ZeeKayDa introduces middleware concerns that are not route-based — for example, the request-time
HTTPS guard from ADR 0004 being applied globally rather than per-endpoint — a separate
`UseZeeKayDaAuth()` middleware registration call may be warranted. This ADR does not introduce any
such concern, but the question should be reviewed when request-time HTTPS enforcement is
generalised beyond the current per-endpoint guard. **Deferred — not blocking this epic.**

### D — Default UI package (`ZeeKayDa.Auth.AspNetCore.UI`) scope

The interaction interface design (§7) deliberately leaves the door open for a future
`ZeeKayDa.Auth.AspNetCore.UI` package that ships optional default pages for login, consent, and
provider selection. These pages would register lower-priority routes that are silently shadowed
by any host-defined route with the same path. This approach is intentionally low-priority: the
core value of ZeeKayDa.Auth is the protocol engine, not the UI. Questions to resolve before
scoping this package: (a) what technology (Razor Pages, Blazor, minimal API + embedded HTML)?
(b) how are the default pages styled/themed?  (c) are they in scope for the current authorization endpoint epic
or a separate follow-up? **Current answer: out of scope for the current epic. Follow-up required.**

### E — ~~Client registration flag name for the `zkd_error` opt-in~~ ✅ Resolved

The opt-in flag name is **`EnableZkdErrorCodes`**. This is consistent with the `Zkd` prefix
convention used across the framework and clearly communicates the feature being enabled.

The flag is a per-client property on the client registration model. Its exact location in the
client registration API depends on the client model design, which is tracked in a separate
high-priority issue and ADR (prerequisite for authorize endpoint implementation).

---

## Spec References

| Reference | Relevance |
|---|---|
| [RFC 6749 §3.1](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1) | Authorization endpoint definition |
| [RFC 6749 §4.1.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1) | Authorization code request parameters |
| [RFC 6749 §4.1.2](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2) | Authorization code response |
| [RFC 6749 §3.1.2.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3) | Redirect URI validation |
| [RFC 6749 §10.12](https://datatracker.ietf.org/doc/html/rfc6749#section-10.12) | CSRF protection via `state` |
| [RFC 7636 §4.3](https://datatracker.ietf.org/doc/html/rfc7636#section-4.3) | PKCE authorization request parameters |
| [RFC 7636 §4.4.1](https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1) | PKCE code verifier validation at token endpoint |
| [OIDC Core §3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) | OIDC authorization request |
| [OIDC Core §3.1.2.6](https://openid.net/specs/openid-connect-core-1_0.html#AuthResponse) | OIDC authorization response |
| [RFC 9700 §2.1.1](https://datatracker.ietf.org/doc/html/rfc9700#section-2.1.1) | PKCE mandatory; `plain` prohibited |
| [OAuth 2.1 §4.1.1 (draft)](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/) | PKCE mandatory for all clients; implicit and ROPC flows removed |
| [RFC 6749 §4.1.2.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1) | Authorization code error response — defined `error` values |
| [RFC 6749 §8.5](https://datatracker.ietf.org/doc/html/rfc6749#section-8.5) | Defining additional error codes; response parameter extensibility |
| [RFC 9700 (general)](https://datatracker.ietf.org/doc/html/rfc9700) | OAuth 2.0 security best practices; information-disclosure caution in error responses |
