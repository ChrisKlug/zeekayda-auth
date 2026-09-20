# Clients and client authentication

Client registration, credentials, and how the token endpoint decides which client is calling.
Implementing a repository is `docs/reference/client-secrets.md` and
`docs/how-to/implement-custom-client-repository.md`.

## Decisions in force

**Clients are statically registered.** RFC 7591 dynamic registration is not in v1: it materially
widens the attack surface of a static-first framework. The v1 abstractions are shaped so a write-side
package can decorate them later without a breaking change.

**A client registration is a pair of interfaces, not a sealed shape.** A custom repository makes its
own ORM entity implement them directly, so lookup on the token endpoint's hot path allocates no
mapping object. `IClientMetadata` carries everything except the credentials and `IClientRegistration`
adds them, so code deciding *what* to issue a client — token issuance above all — never receives its
secrets; only client authentication takes `IClientRegistration`. The inheritance means a downcast
still reaches them, which is the point: a guardrail against accidental use, not a boundary against a
determined caller, who could resolve the repository anyway. The framework ships a sealed record implementation for hosts that want one, and validation
lives in a separate validator rather than in a constructor, so a test can construct an invalid
registration deliberately.

**String sets on a registration are compared ordinally and counted by enumeration, and the
resolver's snapshot guarantees both for everything the framework serves.** A custom repository's
entity type is free to build a set with `OrdinalIgnoreCase`, which would silently widen a
redirect-URI or auth-method allowlist, or to report fewer entries than it yields, which let a 33rd
redirect URI past the cap and `{ "none", "client_secret_basic" }` past the `IsPublic` rule. The
snapshot rebuilds the four sets with `StringComparer.Ordinal` from what they enumerate. Code reading
a registration straight from a repository — the snapshot's copy, the registration validator (which a
custom repository calls on its own entity) and the startup check of in-memory clients' scopes —
still compares explicitly and counts by enumerating: swapping such a loop for `.Count` or
`.Contains` changes behaviour, and the `MiscountingSet` tests pin it. Framework code past the
snapshot compares explicitly too, so a path that skips it stays safe.

**`IsPublic` is declared, never derived, and the three-way consistency rule is enforced at
registration:** public ⇔ no credentials ⇔ auth methods are exactly `{ "none" }`. A default
interface method computing it would let a configuration omission quietly change security behaviour
instead of failing a startup check. A default interface method is used only where the default is
the safe or the forward-compatible answer, never to excuse an omission: the signing-algorithm
allowlist (`null` inherits the server default), `AllowedPromptValues` (empty permits every value, so
a new one needs no change), `DisplayName` and `InitiateLoginUri` (`null`: none), `RequireConsent` (`true`: an
implementation that says nothing requires consent), `RequirePkce` (`true`: a
registration that says nothing is held to PKCE), the two token lifetimes (`null`: the server's
validated value) and the three claim additions (empty: a registration that says nothing widens
nothing). Every one of them is in the registration fingerprint, because each changes what a
client is issued; a test fails the build when a member is added to either interface and not to it.

**A client's claim additions are selectors, never sources, and never remove.** `AdditionalIdTokenClaims`,
`AdditionalUserInfoClaims` and `AdditionalAccessTokenClaims` widen what the granted scopes unlock for
every grant to the client; a type still has to come back from the claims provider to appear anywhere,
and removal is `AllowedScopes`. The registration validator refuses a null collection, a blank entry and
a reserved protocol name; whether an addition names a claim a scope unlocks is checked per grant
against the scope repository, which the validator's cached verdict cannot see
(`token-issuance-and-claims.md`).

**Credential type identity is the algorithm; there is no string discriminator and no
`string? ClientSecret`.** A bare string is ambiguous about plaintext versus hash and pushes fixed-time
comparison onto every implementer; an `Algorithm` discriminator grows a central switch without bound.
Adding bcrypt means a credential sub-interface with its `IClientCredential.Snapshot()`, and a paired
hasher — no framework change. `IPbkdf2ClientSecret` declares its copy as a default the same way, so
the framework's own type is not special-cased. A `Snapshot()` returning itself or `null` fails
validation as `client.credentials.not_copied`; one still sharing a buffer is the implementer's bug.

**Verification is always fixed-time and never throws.** A hasher returns `false` on internal error
rather than propagating, so an exception cannot become a timing or behavioural oracle. The shipped
default is PBKDF2-HMAC-SHA256 with a 600,000-iteration floor (current OWASP guidance), enforced both
where a credential is created and where a pre-hashed one is imported — a credential migrated from
another IdP bypasses the constructor entirely, so the import check is the only thing standing between
a weak stored hash and production. At most two active shared secrets per client, to make rotation
possible; authenticators try both before failing.

**Failure paths are padded to a fixed two-credential budget; the success path is not.** Padding
verifies against a decoy the default hasher builds once at startup: it costs a full verification, and
no known value verifies it. The built-in PBKDF2 decoy is random bytes, free to build; a custom default
hasher pays one `Create` and cannot supply a cheaper decoy. The budget is burned on every path with
nothing real to verify: unknown client, a method outside the server's or the client's allowlist, an
empty secret, and every `none` rejection. A non-default hasher's failure is padded too, so a faster
custom hasher cannot reopen the oracle. A client mid-rotation is thus not timing-distinguishable from
an unknown one, nor "public client rejected" from "no such client". Successful `none` authentication
is deliberately *not* padded: the outcome is visible in the HTTP response and `client_id` is not an
OAuth secret. Enumeration by request volume is left to rate limiting (RFC 9700 §2.1).

**The composite hasher is registered as its own concrete type, never as the hasher interface.**
Registering it under the interface would let it be injected into its own `IEnumerable<>` dependency
and recurse on the first verification. Multiple registered hashers require one explicit default;
ambiguity is a startup failure, not a silent pick.

**Authenticators are self-describing; the composite has zero method-specific knowledge.** Each
authenticator declares the method strings it owns and detects its own request shape, so adding mTLS
means implementing, registering, and adding the method string to the server allowlist — the composite
never changes. Startup validation requires every advertised server method to have exactly one owning
authenticator. `none` must never be declared by any authenticator: it is the composite's fallback
after every credential-bearing authenticator has declined, because a generic "no evidence"
authenticator cannot know about custom mechanisms and would collide with them.

**The composite defends against its own extension point.** More than one matching authenticator is
`invalid_client` (RFC 6749 §2.3). An exception thrown from a shape check is logged and treated as
non-matching rather than failing the request. A returned method not in the authenticator's own
declared set is rejected — otherwise a buggy detector could route past the startup coverage check.
Repository lookup is deferred until after the cheap rejections, so an ambiguous request costs no I/O.

**Redirect URI matching is exact and ordinal — no prefix, normalisation or wildcard.** `http` is
accepted only for loopback, where the port varies (RFC 8252 §7.3); the loopback test is a whole-string
match so `localhost.attacker.com` fails. Fragments, userinfo and path traversal are rejected, the URI
count is capped, and the scheme rule is a **pure allowlist** — `https` on any host, `http` on
loopback, and any private-use scheme containing a dot (RFC 8252 §7.1). No blocklist is maintained,
because every dangerous scheme (`javascript`, `data`, `file`) lacks a dot and the allowlist rejects it
without being told about it. An `http://localhost` URI logs an advisory warning recommending the IP
literal (RFC 8252 §8.3); `https://localhost` does not, being a web client on a dev certificate rather
than a native loopback redirect. Post-logout redirect URIs get the same treatment.

**A registration whose credential no registered hasher can handle is a startup failure, and so is one
whose credential accepts an empty presented secret.** Both would otherwise surface at runtime as an
ordinary `invalid_client`, indistinguishable from a wrong password — or, for the empty-secret case,
as unauthenticated access.

**The resolver serves a snapshot, never the store's instance.** A repository may return an entity
still attached to a change tracker, so validating what it handed back validated nothing durable — one
set of redirect URIs approved, another matched against. `ValidatedClientResolver` copies every member
into a `ClientRegistrationSnapshot` before reading it twice, then fingerprints, validates and returns
the copy. Collections are rebuilt *and* wrapped against a downcast, because `TokenIssuanceContext.Client`
hands the registration to the host's own `ITokenIssuer`. An uncopied member is not a compile error, so
`Snapshot_covers_every_IClientRegistration_member` and
`A_snapshot_carries_every_value_of_the_registration_it_copied` enforce it. Credentials copy themselves.

**Client lookup returns `null` for unknown or malformed ids and never throws.** Throwing changes
timing and leaks a signal usable for client-ID enumeration. `invalid_client` covers both unknown
client and wrong credential, `error_description` never contains the `client_id`, and any opt-in
sub-code must not distinguish the two either. Presented secrets, raw `Authorization` headers, raw
token-endpoint bodies and `code_verifier` values are never logged (RFC 7636 §7.5).

**Every registration is validated where it is served, not only where it is written.** The iteration
floor, the two-secret cap, the `IsPublic` rule and the rules holding a client to what the server
serves are enforced by `ValidatedClientResolver`, the only path from a `client_id` to a registration:
it runs the full validator on what the repository returned and serves a failing one as an unknown
client. `ZEEKAYDA0003` is not a second guarantee — it warns only that an out-of-assembly repository
never references the validator, a reference and not a call.

**Client-facing types split on whether they need a request.** Registrations, credentials, hashers,
the repository and the validator are core; the authenticator seam and its request context types live
in the ASP.NET Core package.

## Tried, didn't work

- **Composite-side request-shape sniffing.** An earlier draft hard-coded "Basic header means
  `client_secret_basic`" in the composite. Caught in review: it defeats the extension point, because
  adding a method would have meant editing the composite.
- **A three-valued authentication outcome.** Needed only for chain-of-responsibility dispatch. Once
  the composite filters candidates first, at most one authenticator ever runs, and the outcome
  collapses to a binary flag.
