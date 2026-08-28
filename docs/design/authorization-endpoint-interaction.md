# Authorization endpoint interaction

**Status: provisional.** Nothing here is built — `/connect/authorize` answers `501`. Originally
ADR 0005 (accepted 2026-07-01, issue #156); revised 2026-08-28 in the S2 shape conversation
(#534/#83), which reversed the interception model and renamed the interaction services. The
security properties and protocol refusals are in `docs/decisions/authorization-and-interaction.md`
and are *not* repeated here.

## Hosting: routed endpoints, and ZeeKayDa is not an authentication scheme

Every ZeeKayDa endpoint — `/connect/authorize` included — is a routed `IZeeKayDaEndpoint` mapped by
`MapZeeKayDaAuth()`, inheriting the route group's HTTPS/421 guard, security headers, issuer-host
constraint and `RequireRateLimiting()` support. GET and POST via `MapMethods`. When interaction is
needed the endpoint calls `ChallengeAsync` on the *provider's* scheme or redirects to the host's
login page — the ordinary ASP.NET Core pattern.

There is no `AddScheme<ZeeKayDaHandler>` anywhere. ZeeKayDa *registers* internal cookie schemes and
*orchestrates* them; every authentication-shaped question is answered by an existing handler
(the cookies answer "who is this?", the provider handlers answer "go get authenticated" and
intercept their own callbacks). A framework scheme would be a vehicle with no cargo.

## Host registration

The host names the providers it wants and nothing else. Callback paths, sign-in schemes, and the
correlation back to the authorization request are the framework's problem. This is the deliberate
difference from IdentityServer/OpenIddict, where the host wires providers against ASP.NET Core
itself and owns the routing between schemes.

```csharp
builder.Services
    .AddZeeKayDaAuth(o =>
    {
        o.Issuer = "https://id.example.com";
        o.AuthorizationEndpoint.Interaction.LoginPath = "/auth/login";
        o.AuthorizationEndpoint.Interaction.ConsentPath = "/consent";
        o.OnSigningIn = async ctx => { /* fires for ALL sign-ins; no interrupt */ };
    })
    .WithProviders(
        auth => auth.AddFacebook(o => { }),
        o => o.OnProviderSignIn = async ctx => await ctx.RedirectToAsync("/collect-more"));
```

`WithProviders` hands out a real `AuthenticationBuilder`, so every existing provider package
(`AddFacebook`, `AddGoogle`, `AddOpenIdConnect`, …) works unchanged. It then forces
`SignInScheme = "zkd.external"` and a `/connect/callback/{scheme}` callback path on every
`RemoteAuthenticationOptions`-derived handler it registered, *after* the host's configuration
callback has run, so neither can be silently overridden.

**Settled: providers stay on `WithProviders`, not inside the options lambda.** The alternative
(`o => o.AddFacebook(...)`) reads better at the call site, and that was the shape originally
sketched, but it cannot hand out an `AuthenticationBuilder` — which would mean reimplementing every
provider package rather than accepting the ones that already exist. Delegating to ASP.NET Core's
own builder is the whole reason a host gets `AddFacebook`, `AddGoogle`, `AddOpenIdConnect` and
anything else on NuGet for free.

## The flow, end to end

```
/connect/authorize          validates (two phases below), writes zkd.interaction; no session →
  → redirect LoginPath      (local)   host page ends with ILoginInteraction.SignInAsync — terminal
  → ChallengeAsync("facebook") (external)  ZeeKayDa sets the handler's RedirectUri itself
      → facebook.com → /connect/callback/facebook   Facebook handler: OAuth mechanics,
                                                    signs into zkd.external
        → /connect/resume   ZeeKayDa endpoint: reads zkd.external, fires OnProviderSignIn,
                            promotes to zkd.session, then consent check → code → client
```

`/connect/resume` is the **external-return landing pad only** — routed, internal, never published
in discovery. It exists because the remote handler ends its request with a redirect that isn't
ZeeKayDa code. Every *host-facing* detour (login, consent, collect-more) instead ends inside a
terminal interaction-service call, which runs ZeeKayDa code in that same request — no bounce needed.

Host code never contains a scheme name, cookie name, callback path or `ReturnUrl`. That is the
invariant every future change is held to. The login page needs no `ReturnUrl` because
`SignInAsync` finds the active interaction in `zkd.interaction` and decides what happens next.

## Internal cookie schemes

`AddZeeKayDaAuth` registers four plain `AddCookie(...)` schemes. Names reserved — a host
registering one fails at startup. All `HttpOnly`, Data-Protection encrypted.

| Scheme | Holds | Lifetime | `SameSite` |
|---|---|---|---|
| `zkd.session` | the SSO session | session | `None` only if `prompt=none` silent auth is supported, else `Lax` |
| `zkd.interaction` | the authorization request context | hard 30 min | `Lax` |
| `zkd.external` | the raw provider callback, before ZeeKayDa reads it | seconds | `Lax` |
| `zkd.pending` | a half-authenticated external principal | hard 15 min, not sliding | `Strict` |

`zkd.pending` is single-use (signed out on `SignInAsync`) and bound to its interaction via a
`zkd:interaction_id` claim. Storage upgrade path: `.UseDistributedCacheInteractionStore()` swaps
the `zkd.interaction` payload for an opaque handle in any `IDistributedCache`.

## Interaction services

One service per page the host builds; the service *is* the protocol knowledge, packaged. Terminal
methods write the redirect response and must be the caller's last action.

```csharp
public interface ILoginInteraction
{
    // Promotes principal to SSO session, continues the flow (consent → code → redirect).
    // Auto-consumes a bound zkd.pending cookie. Terminal. Throws ZeeKayDaInteractionException
    // if no interaction is active (see #593 for the future [Authorize]-driven mode).
    Task SignInAsync(ClaimsPrincipal principal, string amr);

    // Null if the pending cookie is absent, expired or misbound — recoverable.
    Task<PendingPrincipal?> GetPendingPrincipalAsync();
}

public interface IConsentInteraction
{
    Task<ConsentRequest> GetRequestAsync();              // client name, requested scopes, user
    Task GrantAsync(IEnumerable<string> grantedScopes);  // terminal; re-intersects
    Task DenyAsync();                                    // terminal; error=access_denied
}
```

Event model: `OnProviderSignIn` (external only) may `RedirectToAsync(path)` (pending principal) or
`DenyAsync(error)`; calling neither promotes automatically. `OnSigningIn` fires for every sign-in
just before promotion, no interrupt; reserved protocol claims (`iss`, `sub`, `aud`, `exp`, `nonce`,
`acr`, `amr`, `zkd:*`) are stripped regardless.

## Request validation (#83)

**The registration a request is validated against is itself validated first.** Endpoints consume an
internal `ValidatedClientResolver` wrapping `IClientRepository`: it runs
`IClientRegistrationValidator` on every served registration (memoized per instance), answers
"unknown client" for one that fails, and logs the failed rule loudly for the operator. Exact-match
is only as trustworthy as the set it matches against; a custom store fed by a typo'd or malicious
database row must not become a redirect target.

**Phase 1 — authenticate the redirect target; failures render locally, never redirect.**
`client_id` present and found; `redirect_uri` present (always required — OIDC rule, even for
single-URI clients) and an exact ordinal match against the registration (loopback port variance
only). Unknown-client and bad-URI render identically. Local rendering: framework-written minimal
400 by default; a configured `ErrorPath` gets a redirect carrying only an opaque error id, details
served by an error-interaction service, never in the query string.

**Phase 2 — everything else; failures redirect with `error` (+ `state` if present, + `iss`
always).** `response_type=code`; `response_mode` absent/`query`; `code_challenge` required,
`S256` only; `request`/`request_uri` → `..._not_supported`; duplicate parameters →
`invalid_request`; unknown parameters ignored; `prompt`/`max_age` parsed now, behavior in #85/#86.
`error_description` stays generic (names the parameter, never echoes a value); the detailed channel
is the opt-in `zkd_error` sub-code per the register.

**Scopes: silent narrow.** Effective scope starts as `requested ∩ client.AllowedScopes`
(RFC 6749 §3.3 sanctions partial ignoring; the granted `scope` is reported in the token response).
Empty intersection → `invalid_scope`. **`openid` is required in v1** — a request without it is
`invalid_scope`; OIDC leaves that behavior unspecified so requiring it is conformant, `nonce`
becomes unconditionally required, and the token endpoint always issues an ID token. Pure OAuth
(no ID token) can be added later without breaking anyone, since loosening validation is
non-breaking. `AuthorizationCodeEntry.Nonce` stays nullable for that day.

## Rejected

- **`IAuthenticationRequestHandler` interception for `/connect/authorize`** (reverses ADR 0005).
  Its GET+POST justification was factually wrong (`MapMethods`), the no-`MapZeeKayDaAuth()`
  ergonomic goal became moot once other endpoints required mapping anyway, and hiding the request
  from the band between `UseAuthentication` and the endpoint protects little — while costing
  hand-rolled HTTPS/header/rate-limit reimplementation and a meaningless scheme registration.
  Provider callbacks never needed ZeeKayDa interception at all: remote handlers intercept their
  own `CallbackPath` natively.
- **A single callback path with `?scheme=X`.** Dispatch on attacker-visible input.
- **ZeeKayDa owning the interaction UI.** Takes away the host's user model, branding, MFA.
- **Full delegation to `ChallengeAsync` + a session cookie, no owned interaction context.** Cannot
  correlate a returning user with the authorization request across concurrent tabs.
- **Merging `zkd.external` and `zkd.pending`.** Forces binding-claim logic into the common path;
  the external handler signs in before ZeeKayDa can attach the binding claim.
- **A `CompleteAsync` separate from `SignInAsync`.** Cognitive load, no benefit.
- **A bespoke interaction-store interface.** `IDistributedCache` already covers the backends.
- **`Helper`/`Service` suffixes for the page services.** Terminal protocol operations are not
  optional conveniences; `*Interaction` says what they are and echoes the seam IdentityServer
  users already know.
- **`redirect_uri` optional for single-URI clients.** A second path through the most
  security-sensitive matching logic, to save one line.
