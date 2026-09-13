# Token issuance and claims

What must be true when a grant becomes tokens. The stores underneath are `token-stores.md` and
`refresh-token-grants.md`; key selection and signing are `signing-keys.md`; what each token carries on
the wire, its audience, its lifetime and its signature are `token-contents.md`.

**The token endpoint issues the authorization code grant with subject claims.** The endpoint writes
the protocol claims from the grant, asks the host's `IClaimsProvider` for the subject's claims, selects
per destination from the granted scopes and the client's registration, and hands a finalized
`TokenPayload` to `ITokenIssuer`, a shape-agnostic seam resolved per `TokenKind` as a keyed DI service
and filled by `JwtTokenIssuer` over the signing key ring. The refresh grant and userinfo are not built;
the entries about them are constraints they inherit.

## Decisions in force

**Refresh-token rotation is mandatory for every client type, and there is no option to disable it.**
RFC 9700 §4.14.2 requires either rotation or sender-constrained tokens for public clients. DPoP and
mTLS are not implemented, so rotation is the only replay defence this framework has, and making it
configurable would mean shipping a supported configuration with none. The store enforces single use;
the endpoint must always issue a successor rather than re-presenting the same handle.

**A rotation that half-applies must be revoked, not left indeterminate.** If persisting the successor
fails *after* the presented token has been marked consumed, the endpoint MUST revoke the family before
propagating the error. The alternative is a family where the presented token is dead and no successor
exists — a state no later request can distinguish from a normal reuse attempt, so the customer is
locked out and the audit trail is wrong.

**The previous-handle hash is forensic only.** A hash, never a raw handle, recorded so a rotation
chain can be reconstructed after an incident, and never consulted to authorize, look up or validate.

**Two copies of a grant's fields, with different authority.** Scope, session id, issued-at, the
previous-handle hash and the original authentication event (`auth_time`, `acr`, `amr`) live only
inside the encrypted payload. Family id, subject, client id, expiry and the family's absolute ceiling
are duplicated as cleartext queryable columns. The **encrypted copy is authoritative for issuance**;
the **columns are authoritative for query, expiry and reuse decisions**, so every security decision is
made before anything is decrypted. Where the two could disagree, the payload is clamped to the column.

**Claims are resolved fresh on every issuance, never snapshotted onto a stored grant.** A refresh
token's own expiry is an idle window reset on every rotation, so under a snapshot model a revoked role
or a disabled subject would never reach an actively-rotating client. Re-fetching bounds staleness to
the access-token lifetime and makes "is this subject still valid?" an answer of the same call.

**The claims seam is mandatory, with no no-op default.** `AddClaimsProvider<T>()` registers the host's
`IClaimsProvider`, scoped; a host without one fails startup with `claims.provider.missing`. An optional
provider with an empty default would let a deployment silently issue claim-less tokens. The framework
never reads an identity store directly.

**There is no fallback to a previous or cached claim set, on either failure path.** `SubjectInvalid`
aborts issuance with `invalid_grant`, under the same description as every other refusal of the grant,
so a client cannot learn that a subject was disabled; an exception, or a `null` result, is an
infrastructure failure and aborts with `server_error`. "Invalid subject" is a distinct type rather than
an empty or null claim list, because "no claims apply to this grant" is legitimate.

**A server fault at the token endpoint is HTTP 500 with `error=server_error`, borrowed knowingly.**
RFC 6749 §5.2's list is closed and every code in it blames the client; `server_error` is defined for
the authorization endpoint (§4.1.2.1). Borrowing it gives a client library something to parse. No
`error_description` names a key, a scope or a claim.

**Both tokens from one issuance come from one resolution.** The access token and the ID token are
selected from one provider result, so neither can reflect a claim change the other does not.

**Caching is the implementer's, keyed on the subject and the family, and bounded well under the
shortest effective access-token lifetime across clients.** A miss on the family id is structurally
"first issuance", so no first-issuance flag exists; the family id is absent at userinfo and is never a
key on its own. A TTL at grant or refresh-token scale defeats the point and must not be used.

**Claims resolution is a subject-level concern.** `ClaimsProviderContext` carries the subject, the
granted scopes, the claim types selection will keep (the union over every destination, a fetch hint
and never a filter) and the family id. The client id and request metadata are withheld: the only
client-varying step is selection, downstream, and a client can only widen what is selected.

**The transfer type is not `System.Security.Claims.Claim`.** Not reliably serialisable, carries a
back-reference to its identity, and its value-type tag never survives a JWT anyway.

**A claim value is a JSON value the provider builds, never an object the framework serialises.**
`ClaimValue` converts implicitly from string, boolean, number and `AddressClaim`, and none of those
conversions throws; a custom shape goes through `ClaimValue.From`, serialised on the spot, snake_case
by default. `ClaimRecord`'s constructor is the one validation point: it refuses a blank type and a
null, empty, NaN, infinite, JSON-null or default value, naming the type and never the value. Repeated
string or number records for one name are written as one JSON array in the order returned (RFC 7519
§4 unique names); any other repeat, or a repeat of a single-valued claim of OpenID Connect Core §5.1,
is a provider bug and aborts issuance as `server_error`.

**Claim selection is configuration, not a seam.** A scope names the claim types it unlocks in each
destination — `IdTokenClaims`, `UserInfoClaims`, `AccessTokenClaims` — and a client registration may
add types to any of them through `AdditionalIdTokenClaims`, `AdditionalUserInfoClaims` and
`AdditionalAccessTokenClaims`, never remove any; removal is `AllowedScopes`. Neither is a source: a
type the provider did not return is omitted, never written `null` or empty (OpenID Connect Core
§5.3.2). Routing is an internal function, so no third party can route a claim the provider never
returned or move a protocol claim.

**An addition may not name a claim any registered scope unlocks in any destination**, so a
consent-bearing claim arrives only through the scope the user can decline. Checked across
destinations, since a per-destination check would let an access-token addition of `email` past the
`email` scope. Checked at startup for the in-memory registrations, and on every authorization request
and every token issuance against the scope set fetched for that request, because the registration
validator's memoised verdict cannot see the scope repository; a collision is the operator's
misconfiguration, answered `server_error` with a generic description and logged with the detail.

**The standard scopes ship their claims in both the ID token and userinfo.** OpenID Connect Core §5.4
routes them to userinfo; §2 lets the ID token carry other claims. A host wanting the §5.4 default trims
the ID-token list with a `with` expression; a future reading of §5.4 as "not in the ID token" is wrong.

**Reserved protocol claim names are stripped from a provider's result before selection**, from one
closed constant compared case-insensitively — `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`,
`auth_time`, `nonce`, `acr`, `amr`, `azp`, `at_hash`, `c_hash`, `sid`, `scope`, `client_id`, `cnf`,
`act` and the `zkd:` namespace — because a resource server's claim lookup is case-insensitive. The
payload builder then adds subject claims to the protocol claims rather than assigning over them, so a
name that somehow survived fails issuance instead of overriding the grant. A registration naming a
reserved claim in an addition fails validation.

**The `claims` request parameter and the `resource` parameter are deferred, not deviated from.** Both
are OPTIONAL; `claims_parameter_supported` stays `false`, and RFC 8707 has no discovery flag. A
`resource` value must later equal a granted scope's audience or answer `invalid_target`.

**Resolved claims may be personal data and never appear in a log entry, an error response, or an
exception message.** A provider's exception is logged through the sanitizing logger, which redacts its
message and keeps its type and stack; selection's own failures name the claim type only; the
provider context prints its scopes and never its subject. The family id is likewise not raw-loggable.

**Userinfo, when built, validates the presented access token as an RFC 9068 §4 resource server** —
signature through the ring, `iss`, `exp`, `typ` of `at+jwt`, `aud` containing the issuer and `openid`
in `scope` — then resolves the pool fresh with a `null` family id, never from anything stored, and
returns `sub` plus the `UserInfoClaims` of the granted scopes and the client's additions. Open for that
issue: how the client is resolved for its additions, what `SubjectInvalid` answers, and whether the
`Claim[]` overload of `IProviderSignInInteraction.SignInAsync` still earns its place now that token
claims come from the provider.

## Tried, didn't work

- **Snapshotting claims onto the stored grant, or reading them from the session principal.** An
  unbounded staleness window under sliding refresh expiry, and a second claims path.
- **An optional provider with a no-op default; a nullable list instead of `SubjectInvalid`.** One
  lets a deployment issue claim-less tokens silently, the other lets a mistaken `null` abort.
- **A string-only or `object?` claim value.** The first forces nonconforming booleans and numbers or
  claim-specific reconstruction in the writer; the second compiles for `null`, a `DateTimeOffset` and a
  domain entity and emits the wrong JSON for each. A value-type tag is not a third option: JWT has no
  channel for it, and Microsoft's own handler drops any it does not recognise.
- **Per-claim destinations, a global always-include list, or resource registries.** Every claim in
  every token is one line here: put it on `openid`. A resource entity exists to answer "who is the
  audience"; a string on the scope answers it.
- **One identity list for both the ID token and userinfo.** Made a userinfo-only claim inexpressible
  and a slim ID token impossible, and the ID token rides in the client's cookie.
- **No `aud` without an API scope; a switch to drop the issuer from `aud`.** RFC 9068 §2.2 makes
  `aud` required, and a toggle that makes our own userinfo reject our own tokens is a supported
  misconfiguration.
- **Selection as a public seam; client-level claim removal; binding additions to a granted scope.**
  A host that wants different routing changes configuration; `AllowedScopes` already subtracts; and
  a client-level addition is operator policy for simple setups, with the guard above keeping every
  consent-bearing claim behind its scope.
