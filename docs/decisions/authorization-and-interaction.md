# Authorization endpoint and user interaction

**None of this is built.** `/connect/authorize` and the provider-callback paths answer `501` today,
and no interaction service, interaction store or consent type exists. What follows is the set of
constraints whoever builds it inherits — protocol refusals, security properties and structural cuts
that are already true of the surrounding code. Interface shapes are deliberately absent here — the
proposed API lives in `docs/design/authorization-endpoint-interaction.md`, which is provisional and
will be revised against the codebase that exists when the work is picked up.

## Decisions in force

**The authorization endpoint and the per-provider callbacks cannot be `IZeeKayDaEndpoint`s.** They
must short-circuit the pipeline before any downstream middleware observes the request, and that is
the whole of the reason. (An earlier version of this entry also claimed a routed endpoint cannot
serve both GET and POST as OIDC Core §3.1.2.1 requires — it can, via `MapMethods`, which the current
`501` stub already does. That reason was wrong and is not load-bearing.) They are therefore
intercepted ahead of routing, and everything `MapZeeKayDaAuth()`'s route group provides has to be
re-applied at that interception point: the HTTPS/`421` guard, the security headers, and the
issuer-host constraint. Discovery, JWKS and the token endpoint stay routed (`endpoints.md`).

**Consequences of intercepting before routing, stated so they are not rediscovered.**
`RequireRateLimiting()` does not apply to these two paths — rate limiting for them has to be
globally-scoped middleware placed ahead of the interception point. `UseForwardedHeaders()` must run
before it in any reverse-proxy deployment, because HTTPS detection depends on it.

**Callback dispatch never reads a user-supplied discriminator.** One path per registered provider,
resolved by the router from the route template — never a single callback path selecting the provider
from a query parameter. Dispatch that trusts attacker-visible request input is the failure this
avoids; cleaner audit logs are a side benefit, not the reason.

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

**The session cookie value is regenerated on every sign-in promotion**, so session-fixation
resistance is a stated property rather than an incidental consequence of whatever
`HttpContext.SignInAsync` does today.

**Framework cookie names are reserved, and a host registering one fails at startup.** Every internal
cookie is `HttpOnly` and Data-Protection encrypted. A session cookie needs `SameSite=None` only if
silent authentication is supported; anything read solely from same-site POSTs takes `Strict`.
Multi-instance deployments must share one Data Protection key ring across all of them — the framework
does not solve distributed key management.

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

Nothing built here yet, so nothing reversed.
