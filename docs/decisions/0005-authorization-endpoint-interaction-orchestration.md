# ADR 0005 — Authorization Endpoint Interaction Orchestration

Status: Accepted   ·   Date: 2026-07-01   ·   Issue: #156

## Decision

`/connect/authorize` and the per-scheme callback paths `/connect/callback/{scheme}` are
intercepted by an `IAuthenticationRequestHandler` registered via `AddScheme<...>` on
`UseAuthentication()` — not by `MapZeeKayDaAuth()`. This is a narrower scope than ADR 0001:
discovery, JWKS, and the token endpoint remain routed `IZeeKayDaEndpoint`s mapped by
`MapZeeKayDaAuth()` (ADR 0001 §1), which is still required. Only the two interaction-heavy,
short-circuiting endpoints use the handler pattern.

**Hybrid ownership model** — ZeeKayDa.Auth and ASP.NET Core split responsibility strictly:

| Concern | Owner |
|---|---|
| Request validation, interaction context lifecycle, SSO session, code issuance, step sequencing | ZeeKayDa.Auth |
| Credential validation, login/consent/provider-selection UI | Host application |
| External provider OAuth2/OIDC mechanics, cookie/session management for those callbacks | ASP.NET Core |

Per-scheme callbacks live at `/connect/callback/{facebook,bankid,google,...}` — one path per
registered scheme, not a single `/connect/provider-callback?scheme=X`. The scheme name is a
route-template value resolved by the router before the handler runs; it is never read from a
user-supplied query parameter, which is the load-bearing reason for per-scheme paths (see Why).

**DI shape:**

```csharp
builder.Services
    .AddZeeKayDaAuth(o =>
    {
        o.Issuer = "https://id.example.com";
        o.AuthorizationEndpoint.Interaction.ConsentPath = "/consent";
        o.OnSigningIn = async ctx => { /* fires for ALL sign-ins; no interrupt */ };
    })
    .WithLocalAuth(o => o.LoginPath = "/auth/login")
    .WithProviders(
        auth => auth.AddFacebook(o => { }),
        o => o.OnProviderSignIn = async ctx => await ctx.RedirectToAsync("/collect-more"));
```

`AddZeeKayDaAuth` registers four internal cookie schemes shared across local and external auth
(session, interaction, external-callback transport, pending-principal); `WithProviders` forces
`SignInScheme = "zkd.external"` on every `RemoteAuthenticationOptions`-derived handler it
registers, after developer configuration, so it cannot be silently overridden.

**Event model — implicit proceed, explicit interrupts only.** `OnProviderSignIn` (external
providers only) may call `ctx.RedirectToAsync(path)` (stores a pending principal, resumes via
`SignInAsync`) or `ctx.DenyAsync(error)`; if neither is called, the principal is promoted and the
code issued automatically. `OnSigningIn` fires for every sign-in path (local, external, custom)
immediately before promotion, has no interrupt capability, and receives a clone of the principal
the host may freely mutate — reserved protocol claims (`iss`, `sub`, `aud`, `exp`, `nonce`, `acr`,
`amr`, `zkd:*`, …) are stripped before token issuance regardless of what the host sets.

**Pending-principal storage — named cookie scheme, not the interaction store.** A half-
authenticated external principal (after `ctx.RedirectToAsync`) is held in an internal
`AddCookie("zkd.pending", ...)` scheme: hard 15-minute TTL (not sliding), single-use (signed out
on `SignInAsync`), bound to the current interaction via a `zkd:interaction_id` claim so it can't
complete a different flow. Reusing ASP.NET Core's cookie auth gives Data Protection encryption
and HttpOnly/Secure/SameSite handling for free. A second internal scheme, `zkd.external`
(seconds-lived, no interaction binding), transports the raw provider callback before ZeeKayDa
has read it — merging the two schemes was rejected because the external handler signs in before
ZeeKayDa can attach the binding claim.

**Interaction context storage — `IDistributedCache`, not a bespoke interface.** Default: an
encrypted `"zkd.interaction"` cookie (Data Protection, hard 30-minute TTL, ~1KB, no server
state). Upgrade path: `.UseDistributedCacheInteractionStore()` swaps the cookie payload for an
opaque ~50-byte handle backed by any `IDistributedCache` (optionally a keyed instance via
`IKeyedServiceProvider`, .NET 8+). No `IAuthorizationInteractionStore` abstraction is defined —
`IDistributedCache` already covers Redis, SQL Server, and custom backends.

**Interaction service interfaces** — the host's only way to advance the protocol state machine:

```csharp
public interface IAuthenticationInteraction
{
    // Promotes principal to SSO session, issues code, redirects. Auto-consumes a bound
    // "zkd.pending" cookie if present. Terminal — writes the response.
    Task SignInAsync(ClaimsPrincipal principal, string amr);

    // Null if pending cookie absent/expired/misbound — caller treats as recoverable.
    Task<PendingPrincipal?> GetPendingPrincipalAsync();
}

public interface IConsentInteraction
{
    Task<ConsentRequest> GetRequestAsync();
    Task GrantAsync(IEnumerable<string> grantedScopes); // re-intersects with requested + client-allowed scopes
    Task DenyAsync(); // redirects with error=access_denied
}
```

All terminal methods write the redirect response and must be the last thing the caller does —
same contract as `HttpContext.SignInAsync`/`ChallengeAsync`. `SignInAsync` throws
`ZeeKayDaInteractionException` if no active interaction context exists.

**Timeout handling never redirects to an unvalidated URI** (RFC 6749 §3.1.2.3 — open-redirect
risk): if the interaction context is gone and `redirect_uri` cannot be recovered, only the error
page is safe. If a validated `redirect_uri` is still recoverable, the framework redirects to the
client with `error=interaction_required` (or `login_required`/etc.) rather than showing a dead
end. The framework never auto-restarts the flow — the relying party decides whether to retry.

**`zkd_error` extension parameter** (RFC 6749 §8.5 permits additional response parameters) is an
opt-in (`EnableZkdErrorCodes` on the client) machine-readable sub-code alongside the spec-defined
`error` value — e.g. `zkd_error=timeout` alongside `error=interaction_required`. It must never
let a non-opted-in-observable distinction leak (RFC 9700 information-disclosure caution); e.g.
`invalid_client`'s sub-codes never distinguish unknown client from wrong credential.

### Security-relevant constraints carried by this design

- **Two-phase authorization request validation** (RFC 6749 §3.1.2.4, §4.1.2.1): phase 1
  (`client_id`, `redirect_uri` shape/match, HTTPS) errors render on `ErrorPath` locally; only
  after `redirect_uri` is authenticated does phase 2 (PKCE, `nonce`, `prompt`, response type,
  …) redirect errors to the client. Collapsing the phases is an open-redirect / error-
  exfiltration vulnerability.
- **Redirect URI: exact byte-for-byte match** — no prefix/normalisation/wildcard matching; loopback
  (RFC 8252 §7.3) is the only case with a variable port.
- **`iss` unconditionally on every response** (RFC 9207) — mix-up attack mitigation (RFC 9700 §4.4).
- **PKCE (S256) is mandatory for every client**, and the implicit flow / ROPC are rejected outright
  — both removed in OAuth 2.1.
- **JAR (RFC 9101) and PAR (RFC 9126) are rejected in v1** (`request`/`request_uri` → 
  `..._not_supported`) — accepting `request_uri` without implementing PAR is an SSRF vector
  (RFC 6819 §4.1.5).
- Only `response_type=code`/`response_mode=query` is supported; `form_post` and `fragment` are
  rejected until a future ADR evaluates their specific threat shapes.
- `state` round-trips byte-for-byte; the framework never inspects its contents — CSRF protection
  on the response remains the relying party's responsibility (RFC 6749 §10.12).
- **Logging must never include** raw `state`/`nonce`/`code_challenge`/codes/tokens/full callback
  URIs, with **no debug toggle to relax this** (RFC 9700 §4.16) — `IAuthenticationRequestHandler`
  runs before ASP.NET Core's own request-logging sanitisation, so the framework must redact the
  callback URI itself. Diagnostics that genuinely need raw values (reproducing a token-exchange
  failure, tracing one RP's interaction) use strongly-typed diagnostic events the host wires up
  **in code**, never a configuration flag — a flag that can log secrets tends to get left on in
  production. Hosts that wire these events take on the same non-disclosure duty the framework
  otherwise owns.
- The SSO session cookie value is regenerated on every `SignInAsync` promotion (the natural
  behaviour of `HttpContext.SignInAsync`) — asserted here so session-fixation resistance isn't
  silently lost in a future refactor.
- All four internal cookies (`zkd.session`, `zkd.interaction`, `zkd.external`, `zkd.pending`) are
  `HttpOnly`, DP-encrypted, and reserved names — a host attempting to register any of them throws
  at startup. `zkd.session` needs `SameSite=None` if `prompt=none` silent auth is supported;
  the others stay `Lax`/`Strict`.
- Host-owned interaction pages (login/consent/provider-selection) are clickjacking targets and
  **must** set `frame-ancestors 'none'` / `X-Frame-Options: DENY` — the framework cannot enforce
  this on host-rendered pages.
- HTTPS enforcement and security headers move into `HandleRequestAsync` (same logic as ADR 0004,
  different interception point, since routing never fires for these two paths); reverse-proxy
  deployments must run `UseForwardedHeaders()` before `UseAuthentication()`.

## Why

- **`IAuthenticationRequestHandler`, not a minimal API route, for `/connect/authorize`**: the
  endpoint must short-circuit the pipeline (challenge/redirect before any downstream middleware
  observes the request) and support both GET and POST (OIDC Core §3.1.2.1). A routed endpoint
  cannot prevent downstream middleware from running.
- **Per-scheme callback paths, not `?scheme=X`**: a query-string discriminator would force the
  handler to trust attacker-visible request input for dispatch; per-scheme paths are resolved by
  the router from the route template instead, and produce cleaner audit logs.
- **ZeeKayDa does not own any interaction UI** (rejected: "black box" model where the framework
  renders login/consent itself) — that would remove the host's ability to bring its own user
  model, identity store, branding, and MFA, and couple the framework to a UI technology.
- **Full delegation to `ChallengeAsync`+session cookie, no owned interaction context** (rejected)
  — breaks down as soon as a flow needs more than one interactive step; without an owned
  interaction context, ZeeKayDa cannot correlate a returning authenticated user with the
  authorization request they were completing, especially across concurrent tabs.
- **Two internal cookie schemes for external sign-in, not one** — merging `zkd.external` and
  `zkd.pending` would force binding-claim logic into the common (no-redirect) path, which never
  needs a pending cookie at all.
- **`CompleteAsync` as a separate method from `SignInAsync`** (rejected) — the distinction added
  cognitive load with no benefit; `SignInAsync` auto-detects and consumes a pending cookie.
- **A ZeeKayDa-specific interaction-store interface** (rejected) — `IDistributedCache` already
  covers every realistic backend (Redis, SQL, custom); a bespoke interface would just be another
  name for the same contract.

## Consequences

The host must implement its own login/consent pages and wire the interaction interfaces — more
code than a framework-shipped default page, accepted in exchange for not constraining the host's
user model or UI stack. `IAuthenticationRequestHandler` ordering (`UseAuthentication()` before
`UseAuthorization()`, and `UseForwardedHeaders()` before `UseAuthentication()` in reverse-proxy
setups) is a hard prerequisite that must be documented prominently, since HTTPS detection depends
on it.
Multi-instance deployments must share the Data Protection key ring across all four cookie
schemes — the framework does not solve distributed key management itself.

Several concerns are intentionally deferred to their own ADRs and referenced here so they don't
drift: the authorization-code/refresh-token store contract (ADR 0008), the client registration
model (ADR 0007, prerequisite for redirect URI sets, allowed scopes, and `EnableZkdErrorCodes`),
claim selection for token contents, cross-endpoint rate limiting (`/connect/authorize` and the
callback path run before routing, so `RequireRateLimiting()` doesn't apply — hosts need
globally-scoped middleware ahead of `UseAuthentication()`), and a possible future
`ZeeKayDa.Auth.AspNetCore.UI` package for default interaction pages.
