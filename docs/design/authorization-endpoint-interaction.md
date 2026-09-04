# Authorization endpoint interaction

**Status: partly built.** Request validation (#83), the interaction context (#84), the local
login handoff, provider registration with its pins, the login dispatch rules and the external
round trip (#85) have landed; consent and code issuance have not, so a request that reaches the
end of what exists answers `501`. Originally
ADR 0005 (accepted 2026-07-01, issue #156); revised 2026-08-28 in the S2 shape conversation
(#534/#83/#84), which reversed the interception model, renamed the interaction services and cut the
interaction store; login dispatch between local sign-in and external providers settled
2026-08-29 (#607); provider registration and callback ownership settled 2026-09-04 (#85). The
security properties and protocol refusals are in
`docs/decisions/authorization-and-interaction.md` and `docs/decisions/interaction-and-session.md`
and are *not* repeated here.

## Hosting: routed endpoints, and ZeeKayDa is not an authentication scheme

Every ZeeKayDa endpoint — `/connect/authorize` included — is a routed `IZeeKayDaEndpoint` mapped by
`MapZeeKayDaAuth()`, inheriting the route group's HTTPS/421 guard, security headers, issuer-host
constraint and `RequireRateLimiting()` support. GET and POST via `MapMethods`. When interaction is
needed the endpoint redirects to the host's login page, or hands the request to the provider's
own handler and lets it challenge.

There is no `AddScheme<ZeeKayDaHandler>` anywhere. ZeeKayDa *registers* internal cookie schemes and
*orchestrates* them; every authentication-shaped question is answered by an existing handler
(the cookies answer "who is this?", the provider handlers answer "go get authenticated" and
complete their own callbacks, invoked from ZeeKayDa's callback endpoints). A framework scheme
would be a vehicle with no cargo.

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
        o.AuthorizationEndpoint.Interaction.SupportsLocalSignIn = true;  // the default
        o.AuthorizationEndpoint.Interaction.ConsentPath = "/consent";
        o.OnSigningIn = async ctx => { /* fires for ALL sign-ins; no interrupt */ };
    })
    .WithProviders(
        auth => auth.AddFacebook(o => { }),
        o => o.OnProviderSignIn = async ctx => await ctx.RedirectToAsync("/collect-more"));
```

`WithProviders` hands out a real `AuthenticationBuilder` over the host's service collection, so
every existing provider package (`AddFacebook`, `AddGoogle`, `AddOpenIdConnect`, …) works
unchanged. Nothing is subclassed, wrapped, renamed or moved to another container. `WithProviders`
may be called more than once; each call takes its own window, and the collision checks run across
calls. The window is the tail of the collection, and the framework checks that it is only that:
it snapshots the descriptors present before the callback and fails registration if any of them was
removed, reordered, or had something inserted ahead of it. A callback that mutates the collection
rather than appending to it could otherwise leave a scheme in the host's map that the replay never
saw, and "unsupported" is not a guarantee — the check is.

### Observe, then take (settled 2026-09-04)

The framework never learns what a callback registered by intercepting it. It counts the service
collection before the callback, and afterwards replays every `IConfigureOptions<AuthenticationOptions>`
instance that appeared into a throwaway `AuthenticationOptions`. Every route into the scheme map —
`builder.AddScheme`, `AddRemoteScheme`, `AddPolicyScheme`, and a raw `IAuthenticationHandler`
added by writing `AuthenticationOptions.AddScheme` directly — ends as that one descriptor, so the
replay sees them identically (verified against ASP.NET Core 10.0 with one of each). What the replay
found is the provider set: `ILoginInteraction.Providers`, and the only names `ChallengeAsync`
will accept.

Then the descriptors are **removed** from the collection. The host's `AuthenticationOptions` never
learns the scheme existed: it is absent from `IAuthenticationSchemeProvider`, `AuthenticationMiddleware`
never dispatches it, `HttpContext.ChallengeAsync("google")` and `[Authorize(AuthenticationSchemes = …)]`
cannot reach it. Everything else the builder registered — the handler type, the named options,
their validation and post-configuration — stays in the shared container, which is exactly and only
what the handler needs to run. Provider schemes live in a framework-owned scheme map and nowhere else.

**What the framework pins, by name, and then asserts.** On every options object whose name is a
registered provider, every `Forward*` member is cleared, since a forward would divert the challenge
or the sign-in around the pinned `RedirectUri` and `SignInScheme` into a scheme the host can see.
On a `RemoteAuthenticationOptions`-derived one, additionally: `CallbackPath` set to
`/connect/callback/{scheme}` under the issuer path, derived exactly as every other endpoint's route
is; `SignInScheme = zkd.external`; and `AccessDeniedPath` cleared, so a provider refusal reaches the
callback endpoint as a failure instead of escaping to a host page. The pin is one open-generic
`IPostConfigureOptions<>` constrained to `AuthenticationSchemeOptions` — the container skips it for
every other options type — registered once, when the first `WithProviders` window closes, so it
runs after the provider's own post-configuration, including the one that defaults `SignInScheme`,
and never moved afterwards: a post-configurer registered later that changes a pinned member is meant
to fail startup, not to be overridden.

The pin alone promises nothing: post-configurers run in registration order, so a
`PostConfigure<GoogleOptions>("Google", …)` registered later by the host or a library would win,
and the provider would sign into the wrong cookie or call back to a path nothing serves. The
promise comes from a matching open-generic `IValidateOptions<>`. Validation always runs after every
post-configurer, and it fails any provider options whose final `CallbackPath`, `SignInScheme`,
`AccessDeniedPath` or `Forward*` differ from the pins, naming the scheme and the member. A startup
activator resolves each registered provider's options once, so the failure surfaces at startup
rather than on the first sign-in. It is an `IStartupActivator`, not a verifier: resolving the
options runs the provider's and the host's own configuration code, which `startup-verification.md`
classes as work, while the verifier that gates the dispatch rules reads only the framework's scheme
map. Nothing in the request path uses reflection; the activator reads the options type off the
handler's base chain, once. A configuration reload re-runs the validator on the next options read,
which fails closed at request time rather than at startup — accepted.

**What the framework does itself, because the middleware no longer does it for these schemes:**

- *Handler activation.* Resolve the handler type from `HttpContext.RequestServices`, falling back
  to `ActivatorUtilities`, then `InitializeAsync(scheme, context)` — the six lines of
  `AuthenticationHandlerProvider.GetHandlerAsync`, without its per-request cache.
- *Callback dispatch.* One routed endpoint **per registered provider** at
  `/connect/callback/{scheme}` under the issuer path, mapped at startup from the scheme map — never
  a pattern matched against request input, and the same route the pin wrote into `CallbackPath`,
  so the handler's own `CallbackPath == Request.Path` check passes by construction. The endpoints
  allow anonymous access, as discovery and JWKS do, so a host fallback policy cannot block them.
  It activates the handler and calls `HandleRequestAsync`, which completes the protocol, signs
  into `zkd.external` with the properties it was challenged with, and redirects to the
  `RedirectUri` ZeeKayDa set: `/connect/resume`. The endpoint owns the other two outcomes. A
  `false` return is a handler declining its own callback — logged at error level, answered with
  an empty 404, never fallen through to the next middleware. An exception is logged by type,
  never by message, since the message embeds the provider's `error_description`, and is then
  classified — only an explicit refusal by the user at the provider becomes `access_denied`. The
  pin installs a framework-owned `OnAccessDenied` on the remote handler, which fires before the
  handler turns the refusal into an `AuthenticationFailureException`; its only effect is to record
  a refusal mark on the same request feature that carries the provider, and nothing of the host's
  runs after it. A host-set `OnAccessDenied` or `EventsType` inside the window fails startup,
  since either would put the refusal outcome outside the framework's control. An exception with
  that mark is a refusal and goes to the client's registered redirect URI as `access_denied`. The
  mark is trustworthy because the handler validates its correlation cookie before it looks at the
  provider's error, so a replayed callback URL cannot produce it; the redirect also requires the
  properties to carry the interaction id `ChallengeAsync` stamped and that id to match the
  `zkd.interaction` cookie, and without the cookie (a `form_post` callback is a cross-site POST
  the `Lax` cookie does not accompany) the refusal renders locally. **Nothing else reaches the
  client from a callback.** Every other exception — a correlation failure, a provider outage, a
  misconfiguration, a handler bug — renders the local error page and leaves the interaction
  untouched, so the user can try again, and a stray or replayed request to a callback route can
  neither complete nor cancel a live authorization request. `server_error` is never sent from
  here: a client that does not hear back is in the same position as one whose user closed the
  tab. A handler outside the base class has no refusal channel, so its failures render locally.
- *Challenge.* `ILoginInteraction.ChallengeAsync` activates the handler and calls its
  `ChallengeAsync` with a `RedirectUri` of `/connect/resume?zkd_i=<id>` under the issuer path,
  derived through the same route helper as the callback, so a path-based issuer completes.

**Startup errors, not silent tolerance.** Invisibility is now a guarantee, so what would break it
fails at startup with a message naming the fix: a provider name outside the grammar — 1 to 64
ASCII letters, digits, `-`, `_` or `.`, never the dot-segments `.` or `..`, compared ordinally,
unique ignoring case, since routing and `PathString` comparison are case-insensitive while scheme
names are ordinal — checked before any route is built; a configure lambda in the window that also sets
`AuthenticationOptions` defaults (they belong on `AddAuthentication`); and any
`IConfigureOptions<AuthenticationOptions>` or `IPostConfigureOptions<AuthenticationOptions>` in the
window that is not a replayable instance — a factory or type registration — because it can neither
be read nor safely removed; and a provider name that also exists in the host's **final** scheme
map, registered before or after `WithProviders` by the host or a library, because the middleware
would then serve that name's callback and the host could challenge it, reintroducing exactly what
removal took away. That last check reads the resolved `IAuthenticationSchemeProvider`, not the
window, so it sees the map as the application will run it.

**The framework trusts no handler for provider identity or interaction binding.** `ChallengeAsync`
stamps the interaction id into the `AuthenticationProperties` it hands the handler. The callback
endpoint knows which provider it is, and marks the request before invoking the handler — a feature
set on the `HttpContext` after routing, never a claim or a property a handler could write;
`zkd.external`, a framework-owned cookie scheme, records that mark as the provider on sign-in and
refuses a sign-in that carries no mark. `/connect/resume` signs `zkd.external` out first, then
refuses when the ticket's interaction id differs from the one it was asked to resume or the recorded
provider is not a registered one. The `.AuthScheme` item `RemoteAuthenticationHandler` stamps into
the properties is a cross-check, never the source. A handler that drops the properties therefore
fails loudly at resume; it cannot complete another interaction or pass as another provider, whatever
it does with the state it was given.

**Handlers that do not derive from `RemoteAuthenticationHandler`** are supported by the same
machinery; only the pin does not apply, because there is no options object to pin. To *complete* a
sign-in such a handler must behave as the base class does: implement
`IAuthenticationRequestHandler`, answer at its callback route, carry the `AuthenticationProperties`
it was challenged with through the round trip, and finish with
`SignInAsync(zkd.external, principal, properties)` followed by a redirect to
`properties.RedirectUri`. That contract is about working, not about safety — the paragraph above is
what keeps a careless handler from breaking a guarantee. One test with a hand-written handler proves
the round trip; one with a handler that drops its properties proves the refusal.

**Unsupported, by consequence:** a provider package that resolves its own scheme through
`IAuthenticationSchemeProvider` (Microsoft.Identity.Web does, and also registers a cookie scheme
of its own inside the callback). Such packages want to own the session; ZeeKayDa is that owner.
Also by consequence: `OpenIdConnectHandler` serves `RemoteSignOutPath` and `SignedOutCallbackPath`
only through middleware dispatch, so upstream front-channel logout and the post-logout return are
unrouted until the logout work (#103, #104) maps per-provider endpoints for them, pinned the same
way. Lost rather than regressed — nothing served them before.

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
  → ChallengeAsync("facebook") (external)  ZeeKayDa activates the Facebook handler and sets its RedirectUri
      → facebook.com → /connect/callback/facebook   ZeeKayDa endpoint hands the request to the
                                                    Facebook handler: OAuth mechanics, signs into
                                                    zkd.external
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

## Login dispatch (#607)

**Local sign-in is not a provider.** An external provider is a redirect out and back — a scheme
registered through `WithProviders`, a remote handler, `zkd.external`, `/connect/resume`. Local
sign-in is an in-process form post that shares none of that lifecycle, so it is a flag —
`InteractionOptions.SupportsLocalSignIn`, default `true` — not a list entry. Modelling it as a
provider would mean a fake scheme or a null object, and the abstraction leaks immediately.

**One page, not two.** The login page is also the provider-selection page: `ILoginInteraction`
exposes `LocalLoginEnabled` and the configured `Providers`, and the host renders a credential form,
a row of provider buttons, or both. No second path option, no second interaction service.

**`LoginPath` presence is the dispatch override — the framework never skips a page the host
built.** An authorization request that needs authentication dispatches:

1. `LoginPath` set → redirect there, always.
2. `LoginPath` unset, local off, exactly one provider → challenge that provider directly. The
   user never sees a ZeeKayDa-controlled page, so cancellation happens at the provider and
   arrives at the callback endpoint as a failure, answered as `access_denied` at the client's
   registered redirect URI (the callback failure path under Host registration; #606 interplay).
3. `LoginPath` unset but the page is needed — local on, or two or more providers → `server_error`
   at the client's redirect, and a startup warning said so first.
4. Local off, no providers → startup **error**.

A host that wants a branding or terms landing page with a single provider sets `LoginPath`; one
that wants the straight-to-provider redirect leaves it unset. Intent is stated by building the
page, which cannot be done by accident. Note the consequence: adding a second provider to a
`LoginPath`-less, local-off host moves it from rule 2 to rule 3 — the framework cannot choose
between two providers, and the startup warning says so.

**Startup checks are gated on `GrantTypesSupported` — there is no separate machine-to-machine
flag.** `GrantTypesSupported` already declares what the server does. When it lacks
`AuthorizationCode`, the interactive machinery is declared unused and none of these checks fire —
that is the clean startup for a `client_credentials`-only host. When it contains
`AuthorizationCode`: rule 4 is a startup error (the message offers all three exits — add a
provider, enable local sign-in, or remove `authorization_code`); rule 3 is a startup warning;
everything else is silent. The conditions are exact, so the warning cries wolf for nobody and has
no built-in expiry date.

### Home realm discovery: decided, deferred (#608)

The framework will offer **configuration-based domain matching only**: a provider registration may
declare the domains it serves, and the framework answers "which configured provider(s) serve this
address" by matching the domain part against that configuration — never by consulting the host's
user store. A per-user lookup is an unauthenticated user-enumeration oracle on the login page
(type an address, learn whether an account exists) and will not become framework API; domain
matching leaks only tenant configuration, which the matched provider's own sign-in page reveals
anyway. A host that wants per-user HRD writes it in its own page against its own store,
deliberately unassisted. The build is #608; nothing in the dispatch shape above precludes it.

## Internal cookie schemes

`AddZeeKayDaAuth` registers four plain `AddCookie(...)` schemes. Names reserved — a host
registering one fails at startup. All `HttpOnly`, Data-Protection encrypted.

| Scheme | Holds | Lifetime | `SameSite` |
|---|---|---|---|
| `zkd.session` | the SSO session | session | `None` only if `prompt=none` silent auth is supported, else `Lax` |
| `zkd.interaction` | the authorization request context | hard 30 min | `Lax` |
| `zkd.external` | the raw provider callback, before ZeeKayDa reads it | seconds | `Lax` |
| `zkd.pending` | a half-authenticated external principal | hard 15 min, not sliding | `Lax` — first read at the end of the provider's redirect chain, which `Strict` withholds it from |

`zkd.pending` is single-use (signed out on `SignInAsync`) and bound to its interaction via a
`zkd:interaction_id` claim.

**As built:** `zkd.session`, `zkd.external` and `zkd.pending` are cookie schemes; `zkd.interaction`
is a Data-Protection payload written directly rather than through a handler — it carries no
principal, so a cookie authentication scheme would be a ticket serializer wrapped around bytes that
are not a ticket. `zkd.session` takes `SameSite=Lax`: the session is read while answering a
top-level GET the user arrived at from the client's site, which is what `Strict` withholds, and
`None` buys nothing until iframe-based silent authentication is supported. `zkd.external` accepts a
sign-in only from a request a provider callback endpoint marked, records that provider into the
ticket, and is consumed by `/connect/resume` whether or not the resume succeeds. `zkd.pending` is
also consumed by a `DenyAsync` at the login page, and carries the provider as a second reserved claim.

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
public interface ILoginInteraction   // scoped, as are all the page services
{
    // Pure configuration — what the page should render. Frozen at startup.
    bool LocalLoginEnabled { get; }                       // InteractionOptions.SupportsLocalSignIn
    IReadOnlyList<ProviderDescriptor> Providers { get; }  // Id + DisplayName, from WithProviders

    // The client asking to be signed in to — ClientId plus the registration's optional
    // DisplayName. Reads the interaction context, so it is zkd_i-bound on SignInAsync's exact
    // terms; a page that dropped the query string fails on its first GET, not at post time.
    Task<ClientInformation> GetClientInformationAsync();

    // Promotes principal to SSO session, continues the flow (consent → code → redirect).
    // Auto-consumes a bound zkd.pending cookie. Terminal. Throws ZeeKayDaInteractionException
    // when the request carries no zkd_i, when there is no interaction context, or when the two
    // name different interactions (see #593 for the future [Authorize]-driven mode).
    Task SignInAsync(ClaimsPrincipal principal, params string[] authenticationMethods);

    // The Cancel button. Ends the request with error=access_denied at the registered redirect
    // URI, establishing no session and leaving an existing one alone. Terminal, zkd_i-bound on
    // SignInAsync's exact terms. Carries a fixed framework error_description naming a cancellation
    // at sign-in; a client needing to branch gets the opt-in zkd_error sub-code, not the prose.
    Task DenyAsync();

    // Starts the external round trip for one configured provider. Terminal, zkd_i-bound on
    // SignInAsync's terms. The id is validated against the configured provider set before any
    // challenge — it selects from a known list, it does not name a target — and an unknown id
    // throws. The endpoint's single-provider auto-redirect runs through this same path.
    Task ChallengeAsync(string provider);

    // Null if the pending cookie is absent, expired or misbound — recoverable.
    Task<PendingPrincipal?> GetPendingPrincipalAsync();
}

public interface IConsentInteraction
{
    Task<ConsentRequest> GetRequestAsync();              // client name, requested scopes, user
    Task GrantAsync(IEnumerable<string> grantedScopes);  // terminal; re-intersects
    Task DenyAsync();                                    // terminal; error=access_denied
}

public sealed class ProviderDescriptor                   // one per scheme WithProviders observed
{
    public string Id { get; }                            // opaque to the host; equals the scheme name
    public string? DisplayName { get; }                  // the scheme's DisplayName, as registered
}

public sealed class ProviderSignInContext                // what OnProviderSignIn receives
{
    public ClaimsPrincipal Principal { get; }            // as the provider returned it, zkd:* stripped
    public ProviderDescriptor Provider { get; }
    public ClientInformation Client { get; }             // the same object GetClientInformationAsync returns
    public IReadOnlyList<string> EffectiveScopes { get; } // requested ∩ allowed, from the interaction context

    // Terminal. Parks Principal — the principal only; the ticket's properties and any saved
    // tokens stay behind — in zkd.pending and redirects to a host-local path carrying zkd_i.
    // The path is validated on LoginPath's terms (InteractionPath.IsSafe): an absolute or
    // protocol-relative value throws before the response is touched.
    public Task RedirectToAsync(PathString path);

    // Terminal. error=access_denied at the client's registered redirect URI with a fixed framework
    // error_description naming the provider stage — ILoginInteraction.DenyAsync's exact terms.
    public Task DenyAsync();
}

public sealed class PendingPrincipal                     // GetPendingPrincipalAsync, on the collect-more page
{
    public ClaimsPrincipal Principal { get; }
    public ProviderDescriptor Provider { get; }
}
```

`ProviderDescriptor.Id` is opaque to the host: it happens to equal the scheme name, but the page
reads it from `Providers` and posts it back, never writes it. The invariant is that no host code
*contains* a scheme name, and round-tripping a framework-handed value does not.
`ClientInformation` carries `ClientId` only until consent (#86) gives the registration a display
name; adding the member then is non-breaking. Configuration lives on properties and request-bound data
behind async methods — a property getter that decrypted cookies and threw on a bad `zkd_i` would
be bad .NET API, so anything read from the interaction context stays a method.

Event model: `OnProviderSignIn` (external only) fires at `/connect/resume` with the context above.
It may `RedirectToAsync(path)` (pending principal) or `DenyAsync()`; calling neither promotes
the principal, so a host with nothing to collect writes no handler. The context reads
the interaction context, so it carries the client and the effective scopes rather than making the
page fetch them; it does not expose the raw provider ticket or tokens.

**Promotion never uses the provider's subject verbatim.** Upstream subjects are unique only within
their issuer, so the session subject of an auto-promoted external principal is derived as
base64url(SHA-256 over the length-prefixed triple of provider id, the subject claim's `Issuer`,
and the upstream sub)): collision-resistant, with length prefixes leaving no separator to collide
on; fixed-length, well inside the 255-character `sub` limit; stable for the life of the upstream
account. The issuer is framework-visible for every handler: a JWT-validating handler stamps the
validated token issuer onto each claim, an OAuth handler stamps `ClaimsIssuer`, which defaults to
the scheme name, and a hand-written handler sets it when it creates the claim. A registration that
validates several issuers therefore separates its users by issuer rather than by promise. A
subject claim carrying `ClaimsIdentity.DefaultIssuer` names no namespace, and promotion refuses it
with a message saying so — a handler that constructs claims without an issuer is one line away
from compliant. Two providers returning the same value cannot share a session or a `sub`. The
provider id is in the hash because the scheme name is the registration's durable identity:
re-registering the same name keeps every subject, which is what an operator rotating a secret or
an endpoint wants, and what an operator moving the name to a *different* upstream must not do —
that is a new provider and needs a new name. A host
that maps external identities onto its own users does so on the page `RedirectToAsync` leads to and
calls `ILoginInteraction.SignInAsync` with its own principal, which consumes the pending one.
`OnSigningIn` fires for every sign-in
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
  Provider callbacks are routed ZeeKayDa endpoints too, one per provider, but the protocol work in
  them is the provider's own handler, invoked — not reimplemented.
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
- **Local sign-in as a provider list entry.** Requires a fake scheme or a null-object provider for
  an in-process form post that shares nothing with the redirect-out-and-back lifecycle; the
  abstraction leaks immediately. It is a flag (#607).
- **A dedicated option to suppress the single-provider auto-redirect.** `LoginPath` presence
  already states the intent; a flag would add a second way to say it and a contradiction to
  resolve (#607).
- **A separate machine-to-machine capability flag.** `GrantTypesSupported` already declares it,
  and a second flag could contradict the first (#607).
- **A per-user home-realm-discovery callback.** An unauthenticated user-enumeration oracle on the
  login page; see the HRD section above (#607).
- **Prefixing provider scheme names as `zkd.<name>`.** Handler options are keyed by scheme name
  (`OptionsMonitor.Get(Scheme.Name)`), so a rename must re-key every name-scoped registration or the
  handler silently receives defaults — an empty `ClientId` failing on first sign-in, not at
  startup — and a provider's own `IValidateOptions` stays bound to the old name and stops running.
  The name is only meaningful inside the framework's scheme map now, so the prefix would buy
  nothing (#85, 2026-09-04).
- **A custom `AuthenticationBuilder` subclass handed to the callback.** Its `AddScheme` overloads
  are virtual, but `AddPolicyScheme` calls the private helper directly and a raw
  `IAuthenticationHandler` registration never touches the builder at all — both land as the same
  descriptor the replay already reads, so the subclass is two holes and a re-implementation of the
  helper for no gain (#85, 2026-09-04).
- **A private service container for provider schemes.** Handlers reach back into
  `HttpContext.RequestServices` for `EventsType`, `SignInAsync` and every `Forward*`, and provider
  packages register arbitrary infrastructure into the collection they are handed; the container has
  no fallback resolution, so isolation means forking the authentication stack and still leaking.
  Removing the scheme-map descriptor gives the same invisibility in the shared container
  (#85, 2026-09-04).
- **Hiding provider schemes behind a decorated `IAuthenticationSchemeProvider`.** Concealment, not
  absence: `GetSchemeAsync(name)` still resolves and every enumerator sees a picture the framework
  authored. Superseded by never registering the scheme with the host (#85, 2026-09-04).
- **Decorating `IAuthenticationService` to refuse provider schemes.** Moot once the schemes are
  not in the host's map (#85, 2026-09-04).
