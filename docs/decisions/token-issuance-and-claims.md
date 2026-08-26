# Token issuance and claims

What must be true when a grant becomes tokens. The stores underneath are `token-stores.md` and
`refresh-token-grants.md`; key selection and signing are `signing-keys.md`.

**The token endpoint is not built** — it answers `501`. The token writer now exists as
`ITokenIssuer` (#521): a shape-agnostic seam taking finalized claims and the client's metadata,
resolved per `TokenKind` as a keyed DI service, with `JwsTokenIssuer` duties filled by
`JwtTokenIssuer` over the signing key ring. Claim *selection* still has no seam — `TokenPayload`
arrives finalized, and the entries below are the constraints that future claims layer inherits.

**A JWT's header is built inside the ring's signing callback, never asserted afterwards.**
`JwtTokenIssuer` reads `kid`/`alg` from the `SigningKey` the ring resolved for that exact call, so a
header disagreeing with its signature is unrepresentable rather than detected. The key is resolved
exactly once per token. A custom JWT issuer keeps this property by signing through
`ISigningKeyRing.SignAsync` and building its header inside the callback — the atomicity guarantee
belongs to that path, not to the `ITokenIssuer` contract itself.

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
locked out and the audit trail is wrong. Turning a partially-applied rotation into a fully-revoked one
is the only outcome the rest of the design can reason about.

**The previous-handle hash is forensic only.** It is a hash, never a raw handle, it is recorded so a
rotation chain can be reconstructed after an incident, and it is never consulted for an authorization
decision or used to look up or validate a prior token.

**Two copies of a grant's fields, with different authority.** Scope, session id, issued-at and the
previous-handle hash live only inside the encrypted payload. Family id, subject, client id, expiry and
the family's absolute ceiling are duplicated as cleartext queryable columns. The **encrypted copy is
authoritative for issuance** — what goes into the next token comes from there. The **columns are
authoritative for query, expiry and reuse decisions**, which is what lets every security decision be
made before anything is decrypted (`refresh-token-grants.md`). Where the two could disagree, the
framework clamps the payload to match the column rather than letting a decrypted value read longer
than what is enforced.

**Claims are resolved fresh on every issuance, never snapshotted onto a stored grant.** A refresh
token's own expiry is an idle window reset on every rotation, so under a snapshot model a revoked role
or a disabled subject would never reach an actively-rotating client — the staleness window is
unbounded, not merely long. Re-fetching bounds it to the access-token lifetime and makes
"is this subject still valid?" a natural result of the same call instead of a second mechanism.

**The claims seam is mandatory, with no no-op default.** An optional provider with an empty default
would let a deployment silently issue claim-less tokens; a missing registration is a startup
configuration failure instead. The framework never reads an identity store directly — that would be
hidden I/O coupling the framework to one store's API with no seam to validate, transform or replace it.

**There is no fallback to a previous or cached claim set, on either failure path.** A subject the
provider reports as invalid aborts issuance with `invalid_grant`; any exception is an infrastructure
failure and aborts with `server_error`. "Invalid subject" is a distinct, explicit outcome rather than
an empty or null claim list, because "no claims apply to this scope" is legitimate and must not be
confused with "this subject must not receive tokens".

**Both tokens from one issuance come from one resolution.** The access token and the ID token are
built from the same result, so there is no split-brain where one reflects a claim change the other
does not.

**Caching is the implementer's, keyed on the family, and bounded well under the access-token
lifetime.** That is the sanctioned way to get snapshot-equivalent I/O without giving up the
call-every-issuance contract. A cache miss on the family id is structurally "first issuance", so no
separate first-issuance-versus-rotation flag is needed and none will be added. A TTL at
grant or refresh-token scale defeats the point entirely and must not be used.

**Claims resolution is a subject-level concern.** The client id and request metadata are deliberately
withheld from it. Client-varying claims belong in a transformation pipeline downstream, not encoded
into this seam as an implementation assumption.

**The transfer type is not `System.Security.Claims.Claim`.** That type is not reliably serialisable,
carries a back-reference to its identity, and has mutable properties with no meaning in a resolution
result.

**Resolved claims may be personal data and never appear in a log entry, an error response, or an
exception message.** By-key redaction covers the logging path; the endpoint itself must not embed a
claim value in any exception or error response it produces. The family id is likewise not
raw-loggable — log a truncated hash.

**Exactly one component assembles the compact JWS, and it is the only caller of the signing service.**
The signing service returns the encoded header and the signature and never a finished token, so `kid`
and `alg` can never disagree with the key that signed; the writer's whole job is
`header "." payload "." signature`. It is named for tokens rather than for JWTs, because the ID token,
the access token and any future format share the one seam.

**No shared signing-plus-encryption abstraction.** Encryption is a sibling seam the writer composes
with when it lands, not a second method on the signing contract — one interface covering both would
force every signing provider to carry a concept it has no equivalent for.

**No JWT encryption in v1, not even an off toggle.** Without dynamic client registration no client can
request an encrypted token, and the encryption discovery fields are OPTIONAL, so their absence is
spec-correct rather than a gap.

## Tried, didn't work

Nothing built here yet, so nothing reversed.
