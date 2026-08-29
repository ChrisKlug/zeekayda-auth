# Authorization endpoint and user interaction

**Partly built.** `/connect/authorize` validates requests, applies the two-phase error model, and
hands an unauthenticated one to the host's login page, which returns through `ILoginInteraction`
and establishes the SSO session. Consent, code issuance and external providers do not exist, so a
request past authentication still answers `501`. Interface shapes for the unbuilt part live in
`docs/design/authorization-endpoint-interaction.md`.

## Decisions in force

**Every ZeeKayDa endpoint is routed — `/connect/authorize` included — and ZeeKayDa is not an
authentication scheme.** The authorize endpoint and the internal external-return endpoint are
`IZeeKayDaEndpoint`s mapped by `MapZeeKayDaAuth()`, inheriting the route group's HTTPS/`421` guard,
security headers, issuer-host constraint and `RequireRateLimiting()` (`endpoints.md`). GET and POST
via `MapMethods` (OIDC Core §3.1.2.1). The framework registers internal *cookie* schemes and
orchestrates existing handlers; no `AddScheme<ZeeKayDaHandler>` exists. Provider callback paths are
intercepted by the providers' own remote handlers — natively, pre-routing — not by ZeeKayDa.

**Callback dispatch never reads a user-supplied discriminator.** One callback path per registered
provider, assigned by the framework and handled by that provider's own handler — never a single
callback path selecting the provider from a query parameter. Dispatch that trusts attacker-visible
request input is the failure this avoids; cleaner audit logs are a side benefit, not the reason.

**No host code ever contains a scheme name, cookie name, callback path or `ReturnUrl`.** The host's
pages advance the flow only through the interaction services. The one concession is `zkd_i`, the
interaction identifier the framework puts on every redirect to a host page, which a page
regenerating its form action from routing must pass back explicitly. It is opaque and never a URL,
so it carries no open-redirect surface — what competing frameworks leave hosts to validate. Any
change requiring a host to name more has broken the design.

**A terminal interaction method completes the interaction it was addressed to, never "the active
one",** and every read and write of interaction state is addressed by that identifier. Without the
binding a sign-in completes whatever context the browser holds, which is what makes *seeding* an
attack: a malicious registered client navigates the victim to an authorization request of its own,
and the victim's later sign-in issues a code the attacker redeems with the PKCE verifier it chose.
PKCE, `state` and `nonce` protect the client against a forged response, not the user against a
request they never started. The lingering variant dies here; the immediate one is consent's answer,
as it is industry-wide. Addressing by identifier also keeps the backing swappable, so no store
interface is invented for a single implementation.

**A client registration is validated by the framework at the point of use, not only at
registration.** Endpoints resolve clients through an internal validating resolver wrapping
`IClientRepository`; a registration failing `IClientRegistrationValidator` is served to the protocol
as unknown-client and logged loudly for the operator. The repository XML-doc contract ("stores MUST
validate before serving") remains, but nothing depends on an implementor honoring it — exact-match
redirect validation is only as trustworthy as the set it matches against.

**Authorization-request validation is two-phase, and collapsing the phases is a vulnerability.**
Phase 1 authenticates `client_id` and the `redirect_uri` (shape, exact match, transport). Only once
`redirect_uri` is authenticated may phase 2 — PKCE, `nonce`, `prompt`, response type — redirect its
errors to the client. A phase-1 error renders locally on the error page. Merging them is an
open-redirect and error-exfiltration hole (RFC 6749 §3.1.2.4, §4.1.2.1).

**No error path ever redirects to an unvalidated URI.** If an interaction context has expired and a
validated `redirect_uri` cannot be recovered, the local error page is the only safe destination. Where
one *is* recoverable, redirect to the client with the spec error (`interaction_required`,
`login_required`, …) rather than showing a dead end. The framework never auto-restarts a flow — the
relying party decides whether to retry.

**PKCE with `S256` is mandatory for every client, with no per-client opt-out** (OAuth 2.1 §7.6).
There is no `RequirePkce` flag on a client registration and there will not be one. The implicit flow
and resource-owner password credentials are not merely disabled — they have no `GrantType` member.

**`nonce` is required whenever `openid` scope is requested**, rejected with `invalid_request` when
absent (OIDC Core §3.1.2.1, §3.1.3.7). **`iss` is returned on every authorization response**,
unconditionally, as mix-up-attack mitigation (RFC 9207, RFC 9700 §4.4).

**`prompt=none` never renders interactive UI** (OIDC Core §3.1.2.1) — login or consent inside a
relying party's silent-auth iframe is a clickjacking vector. It succeeds only against an existing
session plus a prior consent grant covering the requested scopes, and otherwise returns
`login_required` / `consent_required` / `account_selection_required` / `interaction_required`.

**JAR (RFC 9101) and PAR (RFC 9126) are refused in v1**, with `request` and `request_uri` answered
`request_not_supported` / `request_uri_not_supported`. Accepting `request_uri` without implementing
PAR is a server-side request forgery vector (RFC 6819 §4.1.5).

**`state` round-trips byte for byte and is never inspected.** CSRF protection on the response is the
relying party's responsibility (RFC 6749 §10.12); the framework neither validates nor derives
anything from the value.

**Nothing raw is logged, and there is no toggle that relaxes it.** Raw `state`, `nonce`,
`code_challenge`, authorization codes, tokens and full callback URIs never reach a log sink (RFC 9700
§4.16). Because interception happens before ASP.NET Core's own request logging, the framework must
redact the callback URI itself rather than relying on the host's pipeline. Diagnostics that genuinely
need raw values are strongly-typed events a host wires up **in code**, never a configuration flag — a
flag that can log secrets gets left on in production. A host wiring those events takes on the same
non-disclosure duty. `code` is a redaction key, so `{Code}` is a poisoned placeholder name here as
everywhere (`errors-and-log-hygiene.md`).

**The SSO session identifier is framework-minted, unguessable and stable for the life of the
session — and is not the cookie value, which is regenerated on every promotion so that
session-fixation resistance is a stated property rather than an accident of what `SignInAsync` does
today.** The identifier is carried as a reserved claim the host neither supplies nor sees and kept
across re-authentication (`prompt=login` and `max_age` refresh `auth_time` only); a fresh sign-in
or a changed subject mints a new one. None of those properties may be traded away: one derived from
the cookie value breaks every binding the moment the cookie rotates, and one tracking authentication
events could never key a denylist. Claims in the reserved `zkd:` namespace are stripped from the
host's principal, or a host copying claims from an inbound token could choose its own identifier.

**Framework cookie names are reserved, and a host registering one fails at startup.** Every internal
cookie is `HttpOnly` and Data-Protection encrypted. A session cookie needs `SameSite=None` only if
silent authentication is supported; anything read solely from same-site POSTs takes `Strict`.
Multi-instance deployments must share one Data Protection key ring across all of them — the framework
does not solve distributed key management.

**The authorization request context lives in the interaction cookie, not a server-side store.**
There is no `IAuthorizationRequestContextStore` and no in-memory default: the context is an
internal, opaque, Data-Protection-encrypted payload, chunked by ASP.NET Core's own
`ChunkingCookieManager`. It carries protocol state and a subject reference — **never claims or a
`ClaimsPrincipal`**, which is what keeps it bounded; the authenticated user lives in the session and
pending cookies. Replay protection belongs to the authorization code, which is already single-use
and server-side; the context authenticates nothing on its own. One cookie holds one interaction, so
a concurrent request in another tab replaces the first, and completing the replaced one is then
refused rather than silently misapplied. A distributed backend, if ever needed, swaps the payload
for an opaque handle without touching public API, lifting that limit with it.

**Authorization request parameters are not length-capped; the encoded context is size-guarded
instead.** `state` and `nonce` stay formally unbounded — RFC 6749 sets no limit, a cap taxes the
honest client, and the careless one just moves its failure elsewhere. The framework refuses at
context-write time when the protected payload exceeds its guard, with `invalid_request`, so an
oversized request fails legibly at the request that caused it rather than as a header some proxy
rejects on the next hop.

**ZeeKayDa owns no interaction UI.** Login, consent and provider selection are the host's pages, and
the host brings its own user model, identity store, branding and MFA. The cost is real: a host writes
more code than a framework-shipped default page would need. The framework also cannot enforce
`frame-ancestors 'none'` / `X-Frame-Options: DENY` on host-rendered pages, and those pages are
clickjacking targets — an unresolved gap, not a solved one.

**Consent re-intersects scopes as a last line of defence.** Effective scope is
`(requested ∩ client.AllowedScopes) ∩ user_granted`; dropped scopes are silently omitted and never
echoed in an error response. The grant path re-applies the intersection so a host bug cannot grant a
scope the client was never registered for.

**A ZeeKayDa-specific error sub-code is opt-in per client and must never leak a distinction the
client is not already entitled to.** RFC 6749 §8.5 permits additional response parameters, so a
machine-readable sub-code may accompany the spec `error` value — but a sub-code must never
distinguish unknown client from wrong credential, and any sub-code that reveals which interaction
step occurred goes only to clients that opted in (RFC 9700 information disclosure).

## Tried, didn't work

- **Pre-routing interception via `IAuthenticationRequestHandler`** (ADR 0005, accepted and
  reviewer-signed-off 2026-07-01; reversed 2026-08-28 in the S2 shape conversation before any code).
  One stated reason was factually wrong (a routed endpoint *can* serve GET and POST — `MapMethods`),
  the no-`MapZeeKayDaAuth()` ergonomic goal was mooted by the other endpoints requiring mapping
  anyway, and hiding the request from middleware between `UseAuthentication` and the endpoint
  protects little — while costing hand-rolled HTTPS/header/rate-limit reimplementation and a
  meaningless scheme registration. Do not re-propose without new facts; the full analysis is in
  `docs/design/authorization-endpoint-interaction.md`.
