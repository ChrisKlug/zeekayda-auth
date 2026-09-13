# Token contents

What each issued token carries on the wire, how long it lives, and what signs it. Where the claims
come from, and which token each lands in, is `token-issuance-and-claims.md`; key selection and
signing are `signing-keys.md`.

**The token endpoint issues the authorization code grant.** The protocol claims, the audiences, the
lifetimes and the signing entries below describe shipped code. The access token's audience is the
issuer alone until scope audiences exist, which is the claims-selection slice.

## Decisions in force

**A JWT's header is built inside the ring's signing callback, never asserted afterwards.**
`JwtTokenIssuer` reads `kid`/`alg` from the `SigningKey` the ring resolved for that exact call, so a
header disagreeing with its signature is unrepresentable rather than detected. The key is resolved
exactly once per token. A custom JWT issuer keeps this property by signing through
`ISigningKeyRing.SignAsync` and building its header inside the callback — the atomicity guarantee
belongs to that path, not to the `ITokenIssuer` contract itself.

**Exactly one component assembles the compact JWS, and it is the only caller of the signing service.**
The signing service returns the encoded header and the signature and never a finished token, so `kid`
and `alg` can never disagree with the key that signed; the writer's whole job is
`header "." payload "." signature`. It is named for tokens rather than for JWTs, because the ID token,
the access token and any future format share the one seam.

**The ID token always carries `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time` and `at_hash`, and
`nonce` on the code grant.** OIDC Core §2 requires the first five, and `nonce` whenever the request had
one, which in v1 is always; an ID token issued on a refresh carries no `nonce` (§12.2 SHOULD NOT).
`auth_time` is REQUIRED after `max_age` or a `claims` request and OPTIONAL otherwise; it is written on
every issuance so there is no path where a client asks and it is missing, and a relying party can apply
its own freshness rule without a round trip. `at_hash` is OPTIONAL in the code flow (§3.1.3.6) and is
written because it binds the ID token to the access token issued with it, so the ID token is assembled
after the access token, which reaches its issuer through the issuance context; the payload stays
finalized, the issuer adds only what depends on the key it resolves, and the framework's JWT issuer
refuses an ID-token issuance handed no access token rather than sign one unbound. The hash function
is the one the ID token's `alg` implies (§3.1.3.6), over the access token's wire value, chosen inside
the signing callback from the key that signs — never from a key read earlier — so like the header it
cannot disagree with the signature. `acr` and `amr` are written when the grant carries
them and omitted otherwise, never `null`.

**`auth_time`, `acr` and `amr` are the grant's original authentication event, on every grant that
descends from an end-user authorization.** On the code grant they come from the authorization code; a
refresh grant carries them in its encrypted payload from family birth, copied verbatim on every
rotation, so a token issued on refresh names the sign-in that started the family — never the
rotation's time. OIDC Core §12.2 makes that a MUST for `auth_time`, and RFC 9068 §2.2.1 fixes all
three across every token derived from one authorization and scopes them to grants involving the
resource owner, so a client-credentials token carries none.

**The ID token has one audience, the requesting client, and no `azp` or `sid`.** §2 allows further
audiences, but nothing in the framework can name one: no `resource` parameter, no registration field,
no flow that hands one ID token to two clients. `azp` is needed when the authorized party is not the
sole audience; here it always is, so the claim would repeat `aud`. `sid` is defined by the logout
specs and must match what a logout token later carries; it is emitted when that work defines the
match, not before. Adding an audience, `azp` and `sid` together is additive.

**The access token always carries `iss`, `exp`, `aud`, `sub`, `client_id`, `iat`, `jti` and
`scope`, under `typ` `at+jwt`.** RFC 9068 §2.2 requires the first seven, §2.2.3 asks for `scope` when
the request had one, which is always, and §2.1 fixes the `typ`. `jti` is a fresh CSPRNG value per
token, never derived from the grant. `auth_time`, `acr` and `amr` follow the ID token's rule; §2.2.1
lets them be issued, so a resource server can gate a call on a fresh or multi-factor login the way a
relying party can.

**The access token's audience is derived from the granted scopes, per RFC 9068 §3.** A scope may name
the absolute URI of the resource server it is for; the token's `aud` is the one distinct such value,
compared ordinally. Two distinct values across the effective scopes is `invalid_scope` at the
authorization endpoint before any interaction, and so is an effective scope string with no
definition, which has no audience to correlate to. Consent and refresh only narrow, so nothing later adds a second one;
every scope string then correlates to exactly one audience, as RFC 9068 §2.2.3 and §5 ask.

**The issuer is always an audience when `openid` is granted, and there is no switch to drop it.**
Userinfo is a protected resource hosted by the issuer, and RFC 9068 §4 obliges a resource server to
reject a token whose `aud` does not name it, so naming the issuer lets userinfo validate as an
ordinary resource server. `aud` is a single string for one recipient, an array for two (RFC 7519
§4.1.3); a token with no `aud` violates RFC 9068 §2.2 and is not issued. Accepted residual: an API
holding a token can call userinfo with it for the claims the user granted that client; only
per-resource tokens via `resource` would close that.

**A scope's audience is an absolute URI with no fragment, checked at startup.** RFC 8707 §2 requires
both of a resource indicator, so the `resource` parameter can later be a pure narrowing filter.

**Lifetimes are server-wide defaults with per-client overrides that inherit when null.** The token
endpoint options hold the access-token and ID-token lifetimes, one hour and five minutes by default;
a client registration may override either, and a null override means the server value. Both must
exceed zero, checked at startup for the server values and by the registration validator for the
client's; there is no upper bound. A lifetime longer than the family's absolute ceiling warns at
startup, as the family sentinel does, and expiry arithmetic saturates rather than throws, so no value
that passed validation fails at issuance. The ID-token default is short because it is consumed once, at the client, on receipt. Nothing else
derives from these values — key retirement is an operator emptying a slot, not a computed window.

**A client whose allowed ID-token algorithms exclude the signing key's algorithm fails closed.** The
ring signs with one key, so `AllowedSigningAlgorithms` must be enforced twice: the registration validator
requires the current signing key's algorithm in the set, and the JWT issuer checks the key the ring
resolved against the client's set, inside the signing callback, before an ID token is built. The
refusal is a throw from the callback, before the signer is touched, and the endpoint answers
`server_error`; the client would have rejected the token anyway, and a log line at our end beats a
silent failure at theirs. ID tokens only, which is what the setting describes — an access
token's algorithm is the resource server's concern. Ordinary rotation never trips this, since a new
key keeps its algorithm; only an algorithm migration does, and the operator widens or clears the
affected sets first. Not a per-algorithm key chooser: several signers would make the self-test, the
startup verification and the header-inside-callback guarantee per-key concerns, to serve an event
most deployments never have.

**No shared signing-plus-encryption abstraction.** Encryption is a sibling seam the writer composes
with when it lands, not a second method on the signing contract — one interface covering both would
force every signing provider to carry a concept it has no equivalent for.

**No JWT encryption in v1, not even an off toggle.** Without dynamic client registration no client can
request an encrypted token, and the encryption discovery fields are OPTIONAL, so their absence is
spec-correct rather than a gap.

## Tried, didn't work

Nothing reversed yet.
