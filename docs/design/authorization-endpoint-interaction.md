# Authorization endpoint interaction

**Status: partly built.** Request validation (#83), the interaction context (#84) and the local
login handoff (#85, local leg) have landed; external providers, consent and code issuance have not,
so a request that reaches the end of what exists answers `501`. Originally
ADR 0005 (accepted 2026-07-01, issue #156); revised 2026-08-28 in the S2 shape conversation
(#534/#83/#84), which reversed the interception model, renamed the interaction services and cut the
interaction store. The security properties and protocol refusals are in
`docs/decisions/authorization-and-interaction.md` and are *not* repeated here.

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
  → LoginPath?zkd_i=<id>    (local)   host page ends with ILoginInteraction.SignInAsync — terminal
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
invariant every future change is held to, with one knowing concession: `zkd_i`, the interaction
identifier the framework puts on every redirect to a host page. The login page still needs no
`ReturnUrl` — `SignInAsync` reads the interaction context and decides what happens next — but it
must carry `zkd_i` back, which an ordinary `<form method="post">` with no `action` does for free
because the browser posts to the current URL including its query string. A form that regenerates
its action from routing (`asp-page`, `asp-controller`) drops it and must pass it back with
`asp-route-zkd_i`. That failure is loud and arrives on the first login test.

**Why the identifier exists at all:** without it, `SignInAsync` completes whatever interaction the
browser is carrying. A malicious registered client can *seed* one — navigate the victim to a valid
authorization request of its own, wait for them to sign in, and collect a code it can redeem, since
it chose the PKCE verifier, `state` and `nonce`. Requiring the identifier to come back through the
page means a user who reached the login page on their own has nothing to attach a planted context
to. It also turns the concurrent-tab case from silently completing the wrong client's request into
a clean error.

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
`zkd:interaction_id` claim.

**Built so far:** `zkd.session` as a cookie scheme, and `zkd.interaction` as a Data-Protection
payload written directly rather than through a handler — it carries no principal, so a cookie
authentication scheme would be a ticket serializer wrapped around bytes that are not a ticket. All
four names are reserved from today regardless, so a host cannot take one and break on upgrade.
`zkd.session` takes `SameSite=Lax`: the session is read while answering a top-level GET the user
arrived at from the client's site, which is what `Strict` withholds, and `None` buys nothing until
iframe-based silent authentication is supported.

## The interaction context

What `/connect/authorize` writes and every later stage reads. **There is no store** — it is an
opaque payload inside `zkd.interaction`, and no `IAuthorizationRequestContextStore` or in-memory
default is built.

| Written at `/connect/authorize` | |
|---|---|
| interaction id | correlates `zkd.pending`; the only value that ever leaves the server |
| `client_id`, validated `redirect_uri` | the response target, authenticated in phase 1 |
| effective scopes | `requested ∩ client.AllowedScopes` |
| `state`, `nonce` | client-controlled, round-tripped untouched |
| `code_challenge` + method | PKCE, carried through to the code |
| `prompt` values, `max_age` | parsed here, behaviour owned by #85/#86 |
| issued-at, hard expiry | 30 minutes |

Accumulated as the flow advances: the authenticating provider scheme, `auth_time`, `amr`/`acr`, a
**subject reference**, and the consent decision with its granted scopes.

**Protocol state and a subject reference only — never claims, never a `ClaimsPrincipal`.** That rule
is what keeps the payload bounded, and it is the one most likely to be broken by accident, by
someone who wants the user right there on the consent page. The authenticated user lives in
`zkd.session` and `zkd.pending`, which are chunked separately.

**Encoding is positional and binary, not JSON** — a version byte then length-prefixed fields, the
shape of ASP.NET Core's own `TicketSerializer`. Field names are ~200 bytes of pure overhead on a
~400-byte payload, and the cookie is re-sent on every request to the path. Nothing is lost by
dropping self-description from a payload only this framework reads. No compression before
encryption: mixing attacker-controlled `state` into a compressed encrypted payload is a needless nod
to CRIME-style length oracles.

**Size: no parameter caps, one guard at the far end.** A typical context is ~400 bytes encoded, ~600
after protection and base64 — a sixth of one cookie. `state` and `nonce` are the only unbounded
fields; capping them would tax honest clients and merely relocate the careless one's failure.
Overflow is `ChunkingCookieManager`'s job (public API, the default manager for any `AddCookie`
scheme and usable standalone, so no chunking is hand-rolled), and a write-time guard on the
protected payload answers `invalid_request` before a request can mint a cookie that a proxy rejects
on the next hop.

**Storage upgrade path**, if the cookie stops being enough:
`.UseDistributedCacheInteractionStore()` swaps the payload for an opaque handle in any
`IDistributedCache`. The payload is internal and opaque, so that is a transport swap with no
public-API consequence — which is what makes the cheap path now a reversible one.

## The SSO session

**The session is the cookie.** `zkd.session` holds it and there is no server-side session record in
v1, on the same reasoning as the interaction context: without the cookie there is no way to know who
the user is, so there is nothing left to store.

**`SsoSessionId` is ZeeKayDa-minted, random and stable for the life of the session.** 128 bits from
`StoreKeyGenerator`, created at promotion inside `ILoginInteraction.SignInAsync` and carried as a
claim in `zkd.session`. The host neither supplies nor sees it. It is **not** the cookie value — that
is regenerated on every sign-in promotion for fixation resistance, while the id is stable from
sign-in to sign-out. Re-authentication (`prompt=login`, `max_age`) refreshes `auth_time` and keeps
the id; a new id is minted on a fresh sign-in, or when the subject changes.

Those three properties — ours, unguessable, stable — are what any later session feature is built on,
and none may be traded away. An id derived from the cookie value breaks every token binding the
moment the cookie rotates. An id that tracks authentication events rather than the session can never
key a denylist or an index.

The id flows session → interaction context → `AuthorizationCodeEntry.SsoSessionId` →
`RefreshTokenEntry.SsoSessionId`. **Code issuance (#87) must not satisfy the `required` member with
a per-code `Guid`.** That is the path of least resistance for a compiler error, it looks exactly
like a session binding, and it is none.

**`sid` is not emitted as an ID token claim in v1.** The claim is defined by the logout specs, and
publishing it advertises a capability that does not exist. It is also a prerequisite for
back-channel logout — the `sid` in a logout token must match one the RP saw in an ID token — so the
two ship together or not at all (#103, #206). Adding a claim later is non-breaking.

### What a cookie-only session reaches

| | |
|---|---|
| `prompt=none`, `max_age`, session lookup | cookie |
| RP-initiated logout (browser present) | cookie: delete it, revoke grants by `SsoSessionId` |
| Back-channel logout to RPs | cookie, including the visited-RP list the spec suggests keeping there |
| Admin or remote termination, logout-all | **needs server-side state** |

Browser-absent termination is the only gap, and every spec-defined logout trigger is browser-present
— RP-initiated logout is browser-mediated by design, and OIDC has no server-to-server "end this
session" call, because that would hand one RP power over every other RP's session. The gap is
deferred to #103/#104.

Its shape when it lands is a **revoked-session denylist plus a `sub` → `sid` index, not a session
store**: persist the sessions that ended, with a TTL of the maximum session lifetime, rather than
every session that lives. That is additive — a row written at promotion, a check on read, the cookie
unchanged — at the cost of a store round-trip on every session read where today there is only a
decrypt.

**Consent grants are not session state.** They outlive the session and the browser, so they need
durable storage whatever is decided here (#86). `prompt=none` needs both: a live session *and* a
prior consent grant.

## Interaction services

One service per page the host builds; the service *is* the protocol knowledge, packaged. Terminal
methods write the redirect response and must be the caller's last action.

```csharp
public interface ILoginInteraction
{
    // Promotes principal to SSO session, continues the flow (consent → code → redirect).
    // Auto-consumes a bound zkd.pending cookie. Terminal. Throws ZeeKayDaInteractionException
    // when the request carries no zkd_i, when there is no interaction context, or when the two
    // name different interactions (see #593 for the future [Authorize]-driven mode).
    Task SignInAsync(ClaimsPrincipal principal, params string[] authenticationMethods);

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
- **`IAuthorizationRequestContextStore` + in-memory default** (the original #84 scope). The context
  needs no server-side identity: it authenticates nothing on its own, replay protection belongs to
  the single-use authorization code, and the concurrent-tab limit comes from correlating through a
  cookie at all — a store does not lift it. A bespoke store interface on top would add public API
  for backends `IDistributedCache` already covers.
- **`Helper`/`Service` suffixes for the page services.** Terminal protocol operations are not
  optional conveniences; `*Interaction` says what they are and echoes the seam IdentityServer
  users already know.
- **`redirect_uri` optional for single-URI clients.** A second path through the most
  security-sensitive matching logic, to save one line.
