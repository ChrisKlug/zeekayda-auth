# Token issuance and claims, explained

Explains `token-issuance-and-claims.md` and `token-contents.md`: how the token endpoint turns an
authorization code into an access token and an ID token, where the claims come from, and how
userinfo answers an access token. Key selection and signing are in `signing-keys.md`, the code store
in `token-stores.md`; principles that apply beyond this part are in `principles.md`.

## The token endpoint

`POST /connect/token` (`TokenRequestHandler`) runs cheap checks before anything costly: the body
must be form-encoded, no parameter may repeat, and `grant_type` must be `authorization_code` with a
`code`, a `redirect_uri` and a well-formed `code_verifier` if one is sent. A server that no longer
serves the code grant refuses before any client is named. The client is authenticated once, and
every later decision reads the registration that authentication checked.

Only the authorization code grant is served. Refresh tokens are neither issued nor redeemed yet; the
refresh token store exists, and a production host supplies one as it does a code store.

## Redeeming the code

`AuthorizationCodeGrant`:

1. A missing `code_verifier` for a client that must use PKCE is refused before the code is touched,
   so the client keeps its code.
2. Redemption is atomic: the store inserts a "redeemed" tombstone with an insert that fails when the
   key exists (`SET NX`, a unique-key `INSERT`), the backing store's one hard rule. The first
   request wins.
3. A replayed code revokes the refresh token family the first redemption started (RFC 6749 §10.5);
   the family id is minted before redeeming so the tombstone carries it.
4. The redirect URI, the PKCE verifier and the client's allowed signing algorithm are checked against
   the stored entry. Every failure is the same `invalid_grant` to the caller; the log says which.
5. The host's claims provider is asked again, so a user disabled since sign-in gets nothing.
6. The access token is issued, then the ID token. A failure anywhere is `server_error`, with nothing
   half-issued.

## Where claims come from

Each scope lists the claims it unlocks for the ID token, the access token and userinfo; a client may
add claims of its own. That gives a **plan**: one list per destination. The host implements
`IClaimsProvider`: given the subject, the scopes and the claim types that will be kept, it returns
claims or says the subject is no longer valid. The client is not passed: claims belong to the user,
and what each client sees is the framework's selection. The framework keeps only what the plan
allows, so a provider returning too much cannot leak a claim the user did not consent to.

Overlapping scopes are merged. A client addition may not name any claim a scope unlocks, since
additions are released without consent; that is checked at startup for in-memory clients and on
every authorize, token and userinfo request for any store. A scope removed under a live grant, two
resource audiences, or a provider that throws or returns null: nothing is issued.

## The tokens

- **Access token** (`typ: at+jwt`, RFC 9068): `iss`, `sub`, `aud` (the issuer, plus the resource
  server a granted scope names), `client_id`, `iat`, `exp`, `jti`, `scope`, `auth_time`, `acr`,
  `amr`, and the plan's access-token claims.
- **ID token** (`typ: JWT`): `aud` is the client, plus `nonce` when the request carried one, and
  `at_hash`, computed inside the signing callback from the key that actually signs.

Everything about the sign-in comes from the stored code entry, never from the token request.
`ITokenIssuer` is public and registered per token kind; `JwtTokenIssuer` is the default for both.

The response is never cached. `invalid_client` is a 401 challenging the scheme the client used, or
a 400 when its credentials came in the form (RFC 6749 §5.2). `scope` is always returned.

## Userinfo

`/connect/userinfo` takes the access token in the `Authorization` header or the form, never both. It
validates the token as a JWT this server signed (signature, `typ`, issuer, audience, expiry, with no
store lookup), requires `openid` (else `insufficient_scope`), looks the client up again, and
answers through the same claims resolver using the userinfo list. CORS comes from an allowlist.

## What it costs

- A sign-in with consent reads the client about five times and the scope catalogue two or three
  times, uncached, so a change takes effect on the next request.
- A custom repository's client-addition clash is caught on the first request, not at startup.
- Userinfo accepts only JWTs this server signed, so replacing the access-token issuer breaks it.

## What the walkthrough changed

The maintainer walked this part at code level. Kept as is: the refresh token store and its startup
requirement, consistent with the code store until refresh tokens land. Filed: an optional caching
decorator for client and scope repositories (#956). Raised for the extension-surface part: a
replaced access-token issuer breaks userinfo.

## What was rejected

- **Claims snapshotted onto the grant, or read from the session.** Unbounded staleness, and a second
  claims path.
- **An optional claims provider with a no-op default.** It would let a deployment issue claim-less
  tokens without noticing.
- **Per-claim destinations, a global always-include list, or resource registries.** A claim in every
  token goes on `openid`; a resource is answered by a string on the scope.
- **Dropping the issuer from `aud`.** RFC 9068 requires `aud`, and our own userinfo would reject our
  own tokens.
