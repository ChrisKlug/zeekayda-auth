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
mapping object. The safe view gets the plain name: `IClient` carries everything but the credentials,
and `IClientWithCredentials` adds them. The resolver's `FindClientAsync` returns `IClient` to every
caller; only client authentication calls `FindClientWithCredentialsAsync`
(`Only_client_storage_and_client_authentication_look_up_credentials`). A downcast still
reaches the secrets: a guardrail against accidental use, not a boundary against a determined caller,
who could resolve the repository anyway. The shipped record `Client` is validated by a separate
validator, not its constructor, so a test can build an invalid registration deliberately.

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

**Every `IClient` member but `ClientId` has a default, and each is the safe answer**, from one
internal `ClientDefaults` the interface, the `Client` record and `ClientOptions` all read
(`The_interface_the_record_and_the_options_default_every_member_alike`). So a store's entity
implements only what it means (`A_custom_entity_implementing_only_its_id_credentials_redirect_URIs_and_scopes_is_a_valid_confidential_client`).
`IsPublic` defaults to `false` and is never computed from the credentials: a public client that
forgets to say so has no secret and fails the three-way rule, enforced at registration — public ⇔ no
credentials ⇔ auth methods exactly `{ "none" }`, which default from `IsPublic`. Redirect, post-logout
and prompt sets, scopes and claim additions are empty (an empty prompt set permits every value);
grant, response type and mode the code flow; consent and PKCE on; logout confirmation shown, zkd
error codes off; the rest `null`. A mistyped implementation compiles and serves the default, so
`Client` and the snapshot must implement every member, as must the fingerprint
(`Every_IClient_member_is_implemented_and_never_left_to_the_interface_default`).

**A client's claim additions are selectors, never sources, and never remove.** `AdditionalIdTokenClaims`,
`AdditionalUserInfoClaims` and `AdditionalAccessTokenClaims` widen what the granted scopes unlock for
every grant to the client; a type still has to come back from the claims provider to appear anywhere,
and removal is `AllowedScopes`. The registration validator refuses a null collection, a blank entry and
a reserved protocol name; whether an addition names a claim a scope unlocks is checked per grant
against the scope repository, which the validator's cached verdict cannot see
(`token-issuance-and-claims.md`).

**A stored secret is a sealed `ClientSecret` holding a PHC string, `$<algorithm id>$...`.** Any store
persists any hasher's output, and a string cannot change after validation, so nothing is copied. The
framework reads only the id (bcrypt is only PHC-like) and calls the hasher that declared it; two
declaring one id fail startup (`Two_hashers_declaring_the_same_algorithm_id_fail_startup`).
`PhcString` is optional. Another credential kind (`private_key_jwt`'s keys) gets its own member.

**Verification is fixed-time, and the framework enforces what a hasher must not do:** a throwing
`Verify` fails the verification (`A_hasher_that_throws_from_Verify_produces_invalid_client_not_a_500`),
blank plaintext never reaches `Create`, and a created secret with an undeclared id is refused.
PBKDF2-HMAC-SHA256 is always registered and creates new secrets unless the host marks its own hasher
`isDefault: true` (`A_host_hasher_marked_default_creates_new_secrets_while_PBKDF2_secrets_still_verify`);
marking two is a startup failure, not a silent pick.
Its 600,000-iteration floor (OWASP) and 2,000,000 cap are enforced where a credential is created
(startup fails, never clamps) and where a pre-hashed one is imported, the only check a credential
migrated from another IdP meets. At most two active shared secrets per client; both are tried.

**Failure paths cost two failed credential slots; the success path is not padded.** A slot is one
verification by *every* registered hasher, the real one plus the others against decoys each builds
once at startup (PBKDF2's is random bytes; a custom hasher pays one `Create`). So a client still
holding an older hasher's secret fails in the same work as an unknown one
(`A_failed_authentication_under_two_hashers_runs_the_same_verifications_as_an_unknown_client`); the
price is every hasher's cost on each failure. Paths with nothing real to verify (unknown client, a
disallowed method, a malformed request, an empty secret, every `none` rejection) spend both slots, so
a client mid-rotation looks like an unknown one. A match is not padded: which rotating secret matched
is hidden from nobody who lacks one. Request-volume enumeration is rate limiting's (RFC 9700 §2.1).

**All padding is inside one public call; callers never count.** `IClientSecrets.Verify(presented,
stored)` pads any failure itself. Malformed requests call it with nothing presented, and the
composite's client-dependent refusals share one padded exit, so a third-party authenticator gets the
same guarantee and no refusal path can forget it. Hasher indexing, decoys and the per-secret
registration checks sit apart, in an internal startup registry.

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

**A malformed secret, one no hasher declared or its hasher refuses, or one whose `Verify` accepts or
throws on an empty secret refuses the whole client**, even beside a valid one
(`One_bad_secret_refuses_the_client_even_when_its_other_secret_is_valid`); the probe runs last. No
framework message quotes a stored value (`no_hasher` names a valid id); a hasher's own text is unchecked.

**The resolver serves a snapshot, never the store's instance.** A repository may return an entity
still attached to a change tracker, so validating what it handed back validated nothing durable — one
set of redirect URIs approved, another matched against. `ValidatedClientResolver` copies every member
into a `ClientRegistrationSnapshot` before reading it twice, then fingerprints, validates and returns
the copy. Collections are rebuilt *and* wrapped against a downcast, because `TokenIssuanceContext.Client`
hands the registration to the host's own `ITokenIssuer`. An uncopied member is not a compile error, so
`Snapshot_covers_every_IClientRegistration_member` and
`A_snapshot_carries_every_value_of_the_registration_it_copied` enforce it.

**Client lookup returns `null` for unknown or malformed ids and never throws.** Throwing changes
timing and leaks a signal usable for client-ID enumeration. `invalid_client` covers both unknown
client and wrong credential, `error_description` never contains the `client_id`, and any opt-in
sub-code must not distinguish the two either. Presented secrets, raw `Authorization` headers, raw
token-endpoint bodies and `code_verifier` values are never logged (RFC 7636 §7.5).

**Every registration is validated where it is served, not only where it is written.** The iteration
floor, the two-secret cap, the `IsPublic` rule and the rules holding a client to what the server
serves are enforced by `ValidatedClientResolver`, the only path from a `client_id` to a registration:
it runs the full validator on what the repository returned and serves a failing one as an unknown
client. A repository never validates its own output; it may still call the validator to reject a
bad client when one is written, for example from an admin UI.

**Client-facing types split on whether they need a request.** Registrations, credentials, hashers,
the repository and the validator are core; the authenticator seam is in the ASP.NET Core package.

## Tried, didn't work

- **Composite-side request-shape sniffing.** An earlier draft hard-coded "Basic header means
  `client_secret_basic`" in the composite. Caught in review: it defeats the extension point, because
  adding a method would have meant editing the composite.
- **Typed per-algorithm secret records.** A store cannot persist a type it has never heard of.
- **A three-valued authentication outcome.** Needed only for chain-of-responsibility dispatch. Once
  the composite filters candidates first, at most one authenticator ever runs, and the outcome
  collapses to a binary flag.
