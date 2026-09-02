# User interaction and the SSO session

**Partly built.** The local login handoff, `ILoginInteraction.SignInAsync` and `DenyAsync`, the SSO
session and the interaction-context cookie exist; external providers, provider selection, consent
and home realm discovery do not. The authorize endpoint's protocol rules are in
`authorization-and-interaction.md`; interface shapes for the unbuilt part are in
`docs/design/authorization-endpoint-interaction.md`.

## Decisions in force

**Callback dispatch never reads a user-supplied discriminator.** One callback path per registered
provider, assigned by the framework and handled by that provider's own handler — never a single
callback path selecting the provider from a query parameter. Dispatch that trusts attacker-visible
request input is the failure this avoids; cleaner audit logs are a side benefit, not the reason.
The provider identifier the login page posts back is request input too, validated against the
configured provider set before any challenge — it selects from a known list, never names a target.

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

**A denial carries a fixed `error_description` naming the stage; the machine-readable
discriminator is the opt-in `zkd_error` sub-code, not the prose.** `access_denied` is the only code
RFC 6749 §4.1.2.1 offers for a cancelled sign-in, a refused consent and a policy refusal alike, so
`DenyAsync()` populates the optional description with framework-owned text naming a cancellation at
sign-in. That text is a courtesy to a developer reading their error page, never a contract. A
client that needs to branch in code will get the `zkd_error` sub-code decision instead — opt-in per
client precisely because which interaction step occurred is a distinction not every client is
entitled to — and that is **not built for authorization responses**: `EnableZkdErrorCodes` governs
token-endpoint responses today, so an authorization denial carries no machine-readable
discriminator at all. Whoever adds one adds it there, not by making the description host-writable.
Naming the stage in prose while gating it in the sub-code is a tension held open deliberately, not
an oversight: a cancelled sign-in that reads as an unqualified refusal is the thing a client most
needs to tell apart, and the wording is the maintainer's to revisit. The description is
framework-owned for the same reason the sub-code is gated — host-supplied text on this channel is a
disclosure primitive, since it reaches the client, browser history and proxy logs, and the phase-2
rule in `docs/design/authorization-endpoint-interaction.md` that a description stays generic and
echoes no value would have no enforcement
left. The denial never becomes a redirect primitive either: the destination is the registered URI
from the decrypted interaction context, so an expired context has no destination and the request
fails where it stands.

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

**Local sign-in is a flag (`SupportsLocalSignIn`, default `true`), not a provider, and `LoginPath`
presence is the dispatch override.** The login page is also the provider-selection page, and the
framework never skips a page the host built: `LoginPath` set → redirect there; unset with local off
and one provider → challenge it directly; unset when the page is needed → `server_error`, warned at
startup; local off with no providers → startup error. Checks fire only when `GrantTypesSupported`
contains `AuthorizationCode` — the existing capability declaration, so a `client_credentials`-only
host starts clean. The conditions are exact: a warning that cries wolf trains people to ignore it.

**Home realm discovery never consults the host's user store.** Framework HRD (deferred, unbuilt) is
domain matching against provider-declared configuration. A per-user lookup on the login page is an
unauthenticated user-enumeration oracle — type an address, learn whether an account exists — and
will not become framework API; domain matching leaks only tenant configuration the matched
provider's own page reveals anyway. Per-user HRD is host code, owning that exposure.

**Consent re-intersects scopes as a last line of defence.** Effective scope is
`(requested ∩ client.AllowedScopes) ∩ user_granted`; dropped scopes are silently omitted and never
echoed in an error response. The grant path re-applies the intersection so a host bug cannot grant a
scope the client was never registered for.
