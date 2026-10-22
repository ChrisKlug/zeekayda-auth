# Sessions and logout

**Status: decided, not built.** The session record below is the foundation for logout propagation
(#103), session-bound refresh tokens (#104), sign out everywhere (#831) and logging out at an
external provider (#1053). Nothing in it exists yet; what the SSO session cookie holds today is
`docs/decisions/signed-in-accounts.md`, which wins wherever the two disagree.

## Why the session needs a server-side record

Today an account's session lives only in the `zkd.session` cookie. That serves every logout the
browser is present for: the end-session request carries the cookie. Two kinds of logout arrive
without it:

- **An upstream provider ends its session.** Back-channel logout is a server-to-server call, and a
  front-channel logout is an iframe in which our `SameSite=Lax` cookie is never sent.
- **A host cuts a user off**: account disabled, deleted or compromised.

With the cookie as the only record, neither can find our session, tell the clients that signed in
through it, or stop the browser's next silent renewal. A client list kept in the cookie as well
would be a second record that can disagree with the first, so the record is server-side only.

## `sid`

The ID token's `sid` is the account's existing session identifier (`zkd:sid`), the same at every
client. Back-Channel and Front-Channel Logout need a `sid` unique only per issuer; Keycloak and
Duende IdentityServer share it the same way. Each account in a multi-account browser has its own,
so a logout token naming one account's session never touches another account.

Once in ID tokens the value is no secret: clients log and store it, and front-channel URLs put it
in access logs. Nothing ever acts on a bare `sid` — only on one inside a token the framework signed.

## The session record

One record per account session, keyed by its `sid`, holding the subject, its expiry, the clients
that took part, and the upstream link when the sign-in came through an external provider.

- **It means "alive".** A session is valid only while its record exists. Sign-in writes it, a
  re-sign-in of the same subject extends it, ending the session deletes it. A lost record means
  signing in again — fail closed.
- **Every request that uses the session reads it**, and a store fault is never read as alive. If
  outages or read cost ever matter, a short in-memory "seen alive" cache bounds the window an ended
  session survives to a few seconds on one instance: a window the framework chooses, not one an
  attacker opens.
- **A client is recorded at code issuance, before the code leaves the server**, so any client that
  could ever receive tokens is on the list when a logout reads it. Each client is its own entry:
  two tabs signing in to two clients at once must both be recorded, never one overwriting the other.
- **The upstream link** is the provider, named by our callback route and never read from a token,
  plus that provider's `sid` and `sub` from its ID token when it carries them — and the provider's
  ID token itself where logging out at the provider is on (#1053).
- **Lookups**: by `sid`; by subject (sign out everywhere); by provider + upstream `sid`; by
  provider + upstream `sub` (a logout token with no `sid` means every session of that user,
  Back-Channel Logout §2.4).
- **Expiry**: every row about a session expires with it, and a re-sign-in extends them all, so a
  client recorded on the first day never drops off before the session ends. Pruning is the
  backend's native expiry, or the first-party package's own pruning service (`token-stores.md`).

It is a new backing contract with its own TestKit fixture, registered by each package's one
`Add…Stores()` call beside the others. None of the existing contracts fits: the code and
interaction stores are key-value with no query by subject or upstream session, and the refresh-token
store's rows are grants.

## Ending a session

- **RP-initiated logout** at the end-session endpoint ends the account the request names
  (`signed-in-accounts.md`), now also deleting its record.
- **Upstream logout** is opt-in per provider; with it off, the provider has no logout endpoint.
  With it on, the matching sessions end like a local logout. This serves front-channel-only
  providers such as Entra ID too, because the lookup needs no cookie.
- **Sign out everywhere** (#831) ends every session of the subject, then revokes the subject's
  `offline_access` refresh tokens.

Ending a session deletes its record, tells every client that took part (the channel is #103's to
design), and makes the session's refresh tokens fail at their next use. Logging the user out at the
external provider when they log out here is a separate opt-in, off by default (#1053): it would
also sign them out of every other app using that provider.

## Refresh tokens

A refresh token issued without `offline_access` belongs to its session: every refresh, and every
code redemption, checks the record and answers `invalid_grant` once it is gone. Ending a session is
then the revocation, with no sweep over the token store. An `offline_access` token never checks the
session and outlives it (OIDC Core §11; Back-Channel Logout §2.7 asks for exactly this split).

A client's registration allows refresh tokens and `offline_access` separately, and the request's
scope picks which kind a code grant gets — so an SPA can rotate short access tokens without ever
holding a credential that survives the user's logout.

Code redemption checks its session *after* storing the new token's family and before returning it,
and sign out everywhere deletes the sessions *before* it revokes tokens by subject. Whichever way a
redemption and a sign-out interleave, one of them sees the other.

## Rejected

- **A client list kept in the cookie.** It cannot be read by a logout that arrives without the
  browser, and alongside a server record it is a second copy that can disagree.
- **A record of ended sessions instead of live ones.** A lost or evicted row would silently sign a
  cut-off user back in.
- **Treating a store fault as alive.** "Store unavailable" is something an attacker can cause —
  flooding a Cosmos account until it throttles is enough — and it would revive ended sessions.
- **A different `sid` per client.** `sub` is already the same at every client, so it hides almost
  nothing. Pairwise subjects would change that, and `sid` goes per client with them if they come.
- **Recording a client at code redemption.** A logout between the redemption's check and its write
  would miss that client for good.
- **Sign out everywhere as refresh-token revocation alone.** The user's live SSO session would hand
  them fresh tokens at the next silent renewal.
