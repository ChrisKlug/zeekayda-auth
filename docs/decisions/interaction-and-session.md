# User interaction and the SSO session

**Partly built.** The local login handoff, the SSO session, the store-backed interaction context,
provider registration through `WithProviders`, the login dispatch rules, the external round
trip and in-flow consent exist; remembered consent grants and home realm discovery do not.
The authorize endpoint's protocol rules are in
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
PKCE, `state` and `nonce` protect the client against a forged response, not the user against a request
they never started. The lingering variant dies here; the immediate one is consent's answer, as it is
industry-wide.

**Terminal means the response is committed, not merely written.** Executing a redirect result sets
the status and `Location` without flushing, so a page that calls a terminal method and then returns
a result of its own replaces both — silently, and for a deny that is the open redirect the
interaction identifier exists to prevent, relocated into host code where nothing validates it. Every
terminal exit therefore starts the response, which turns that page into an exception the first time
it runs. `CompleteAsync` does not do this and `HasStarted` stays false; only `StartAsync` does. The
protection must be explicit rather than inherited from whatever the result happens to write: a
response with a body commits itself, so a terminal path that ends in one is safe by accident and
stops being safe the moment it becomes a redirect.

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
echoes no value would have no enforcement left. The denial never becomes a redirect primitive
either: the destination is the registered URI from the decrypted interaction context, so an expired
context has no destination and the request fails where it stands.

**The SSO session identifier is framework-minted, unguessable and stable for the life of the
session — and is not the cookie value, which is regenerated on every promotion so that
session-fixation resistance is a stated property rather than an accident of what `SignInAsync` does
today.** The identifier is carried as a reserved claim the host neither supplies nor sees and kept
across re-authentication (`prompt=login` and `max_age` refresh `auth_time` only); a fresh sign-in
or a changed subject mints a new one. None of those properties may be traded away: one derived from
the cookie value breaks every binding the moment the cookie rotates, and one tracking authentication
events could never key a denylist. Claims in the reserved `zkd:` namespace are stripped from the
host's principal, or a host copying claims from an inbound token could choose its own identifier.

**Framework cookie names are reserved, the `zkd.interaction.` prefix included; a host registering one
fails at startup.** Every internal cookie is `HttpOnly`; tickets are Data-Protection encrypted, and
the binding cookies hold a random secret. A session cookie needs `SameSite=None` only if silent
authentication is supported; the rest take `Lax`, `zkd.pending` included, because its first read is the
page at the end of the provider's redirect chain and `Strict` is withheld from a navigation initiated
cross-site — a control that silently breaks the feature is no control. Multi-instance deployments must
share one Data Protection key ring across all of them — the framework does not solve distributed key management.

**The authorization request context lives in the interaction store, one encrypted entry per
interaction, so any number can be in flight in one browser and none has a size ceiling.** It carries
protocol state and a subject reference — **never claims or a `ClaimsPrincipal`**. The seam is internal
with two implementations, a per-process dictionary and the host's `IDistributedCache`; set, get and
remove is the whole contract, so a shared cache is a complete answer for a multi-instance host, while
the per-process `MemoryDistributedCache` fails startup outside `Development` unless opted out (`Critical`).

**Each interaction is bound to its browser by `zkd.interaction.<id>`, a random secret; the store key
is derived from identifier and secret together.** The identifier travels in URLs and URLs leak; a
browser without the cookie, or with a forged one, finds nothing. Each cookie expires with its interaction
and is deleted when it ends; capped at ten per browser in sequence, oldest first, so ninety-byte bindings
do not reopen the header-budget finding a 3 KB payload per cookie would have. Simultaneous tabs overshoot
by their count, which cross-site content cannot force: a browser stores these cookies only on a top-level
navigation. A failed request never wrote an interaction and clears none.

**One code per interaction, decided by the authorization code store.** Before minting a code, issuance
claims the interaction through the code store's atomic insert-if-absent, expiring with the interaction
plus skew, then re-checks its expiry — after the claim, so a stalled response cannot claim again once the
winner's claim lapsed. A loser or a late response issues nothing and refuses as a replayed form is refused.

**ZeeKayDa owns no interaction UI.** Login, consent and provider selection are the host's pages, and
the host brings its own user model, identity store, branding and MFA. The cost is real: a host writes
more code than a framework-shipped default page would need. The response a consent page calls
`GetRequestAsync` from — it cannot render without — is stamped `frame-ancestors 'none'`,
`X-Frame-Options: DENY` and `no-store`; the login page has no such call and is still frameable.

**Provider schemes exist only in the framework's scheme map, and what would make them visible to
the host fails at startup.** `WithProviders` replays the scheme-map configurers the host's callback
appended, records the schemes, and removes the configurers, so a provider is absent from the host's
`AuthenticationOptions`: not enumerable, not challengeable by name, never dispatched by the
middleware. Invisibility is a guarantee rather than a convention, which is why a provider name the
host also registers as a scheme of its own is a startup error and not a shadowing rule. The
framework pins every provider's forwarding and each remote handler's callback path, sign-in scheme
and access-denied path by name, and *asserts* the pins with a validator resolved at startup, because a
post-configurer registered later would otherwise win silently and send the sign-in to the wrong
cookie or the callback to a path nothing serves. A host remote scheme whose callback path is a
provider's route is refused for the same reason: the middleware would claim the callback first.

**No handler is trusted for provider identity or interaction binding.** The challenge stamps the
interaction identifier into the properties it hands the handler; the callback endpoint marks the
request with the provider its route names before the handler runs; `zkd.external` records that
mark at sign-in and refuses a sign-in without one; `/connect/resume` consumes the ticket first and
refuses one naming another interaction or an unregistered provider. A handler that drops its
properties fails loudly there and can complete nothing else. Only a refusal by the user at the
provider reaches the client — recorded by the framework's own pinned access-denied event, and only
for the interaction the browser carries; every other callback failure renders locally, logged by
type never by message, and leaves the interaction alive. The session subject of an auto-promoted
external principal is derived from provider, claim issuer and upstream subject together, never the
upstream value: two providers can never share a session, and a subject without an issuer is refused.

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
