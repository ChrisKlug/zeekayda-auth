# Authorization endpoint and user interaction

**Built through code issuance.** `/connect/authorize` validates requests, applies the two-phase
error model, hands an unauthenticated one to the host's login page or an external provider, an
authenticated one to the host's consent page, which returns through `IConsentInteraction`, and
answers a request past both with an authorization code at the registered redirect URI. Remembered
consent grants are the unbuilt part (#632). Interface shapes:
`docs/design/authorization-endpoint-interaction.md`; the interaction surface, cookies and SSO
session: `interaction-and-session.md`; the code store: `token-stores.md`.

## Decisions in force

**Every ZeeKayDa endpoint is routed — `/connect/authorize` included — and ZeeKayDa is not an
authentication scheme.** The authorize endpoint and the internal external-return endpoint are
`IZeeKayDaEndpoint`s mapped by `MapZeeKayDaAuth()`, inheriting the route group's HTTPS/`421` guard,
security headers, issuer-host constraint and `RequireRateLimiting()` (`endpoints.md`). GET and POST
via `MapMethods` (OIDC Core §3.1.2.1). The framework registers internal *cookie* schemes and
orchestrates existing handlers; no `AddScheme<ZeeKayDaHandler>` exists. Provider schemes are never
registered with the host's `AuthenticationOptions`: `WithProviders` replays what the host's callback
added, keeps it in a framework-owned scheme map, and removes the registration, so the host cannot
enumerate, challenge or authorize against a provider. Each provider's callback is a routed ZeeKayDa
endpoint of its own that hands the request to that provider's handler, and every remote handler's
callback path, sign-in scheme and forwarding are pinned by the framework after host configuration
and asserted at startup, so a later registration that changes them fails the host, not the flow.

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

**Consent is asked of every user for every client on first use, and only a remembered grant or a
per-registration opt-out skips it.** The consent page is the one thing between a sign-in and an
issued code for a request the user never started — a malicious registered client navigating a
victim to a valid request of its own — so no default skips it. `IClientMetadata.RequireConsent`
(default `true`, a default interface member so an implementation that never heard of it keeps it)
is the opt-out, for an operator's own first-party applications and nothing else; a registration
that sets it false accepts that attack unmitigated for that client. `prompt=consent` sends even an
opt-out client to the page, and answers `consent_required` when the host has none. Remembered
grants are unbuilt: every request prompts, and `prompt=none` for a client requiring consent
answers `consent_required` — not yet, rather than a reversal of the paragraph above.

**A consent decision is recorded by the session it was asked of.** Every `IConsentInteraction`
method is `zkd_i`-bound on the login service's terms and additionally refuses when the session
cookie no longer names the session and subject that authenticated the request — a sign-out, or a
sign-in as someone else, between the handoff and the answer. A grant can only narrow the request:
it is re-intersected with the effective scopes, and one that drops `openid` is a refusal to be
identified, answered `access_denied` as a deny is. The client is resolved again at every step — the
post-authentication dispatch and each consent call — and must still list the request's redirect
URI, so a registration removed or narrowed mid-flow ends the request where it stands, never at a
redirect URI that no longer belongs to anyone.

**A consent decision is never persisted: it is taken, the code issued and the interaction
discarded in the one response.** Nothing is left on the interaction for a replayed consent `POST`
to re-record or for a later sign-in to pick up; the second `POST` finds no interaction at all. The
code binds what the interaction context carries — the SSO session identifier, the subject, the
authentication time, the PKCE challenge, the nonce — and never a value minted at issuance; a
per-code identifier in the session's place would look like a session binding and be none. The
scopes written into the code are those present in all of the request's effective scopes, the
allowed scopes of the registration as it is at issuance, and the user's grant when consent was
asked; a registration that no longer allows `openid` ends the request as one that dropped its
redirect URI does. Issuance asserts its preconditions rather than re-establishing them: a context
without a session, or one for a consent-requiring client without a decision, is a caller error
and throws, because every path that reaches issuance bound the session and recorded the decision
first, and re-reading the session cookie there would see the cookie the sign-in request arrived
with rather than the one its response is writing. A store failure answers the client
`server_error` with nothing issued, and discards the interaction like every other failure.

**A terminal page-service method accepts only a `POST`, checked before any state is read.** The
framework arrives at a host page with a `GET`, and its `Lax` cookies accompany a top-level `GET`
from anywhere, so a decision wired to the rendering request would be taken on arrival, and a
cancel wired to a link could be triggered by a page that never showed the user anything.

**A missing `ConsentPath` is a request-time `server_error` with an error log, not a startup
warning.** Whether the page is needed depends on client data the framework does not enumerate at
startup, and a warning that fires for every all-first-party host is one that gets ignored.

**JAR (RFC 9101) and PAR (RFC 9126) are refused in v1**, with `request` and `request_uri` answered
`request_not_supported` / `request_uri_not_supported`. Accepting `request_uri` without implementing
PAR is a server-side request forgery vector (RFC 6819 §4.1.5).

**`state` round-trips byte for byte and is never inspected.** CSRF protection on the response is the
relying party's responsibility (RFC 6749 §10.12); the framework neither validates nor derives
anything from the value.

**Nothing raw is logged, and there is no toggle that relaxes it.** Raw `state`, `nonce`,
`code_challenge`, authorization codes, tokens and full callback URIs never reach a log sink
(RFC 9700 §4.16), and the framework redacts the callback URI itself rather than relying on the
host's pipeline. A response to the client is written as two headers by the framework, never
through `Results.Redirect`, whose executor logs the full `Location` — code and `state` included —
at `Information`. Diagnostics that genuinely need raw values are strongly-typed events a host wires
up **in code**, never a configuration flag — a flag that can log secrets gets left on in
production, and a host wiring the events takes on the same non-disclosure duty. `code` is a
redaction key, so `{Code}` is a poisoned placeholder name here as everywhere
(`errors-and-log-hygiene.md`).

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
