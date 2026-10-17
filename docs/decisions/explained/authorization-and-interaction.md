# The authorize flow and interaction, explained

Explains `authorization-and-interaction.md`: what happens from the moment a client sends the
browser to `/connect/authorize` until the browser goes back with a code or an error. Principles that
apply beyond this part are in `principles.md`.

## What it is for

The host owns the pages (login, consent, external sign-in follow-up) and the framework owns the
protocol. A page never touches a return URL, a cookie or the raw request; it calls an interaction
service, and the framework decides where the browser goes next.

## The flow

**The endpoint** (`AuthorizationEndpoint`) is served only with the authorization code grant. It
marks every response `no-store`, reads the query (GET) or form (POST), and validates in two phases:

- **Local error:** the client or its redirect URI could not be confirmed, so the error page is
  rendered here and nothing redirects, or the endpoint would be an open redirect.
- **Redirect error:** the client and redirect URI check out, so the error goes back to the client.
- **Valid:** an interaction starts.

**Starting the interaction.** The SSO session is read, and the request needs a sign-in when there is
none, the client sent `prompt=login`, or the session is older than `max_age`. A `prompt=none`
request that needs a sign-in is answered `login_required` there, before anything is stored. Otherwise
the validated request is stored under a random id; from then on only that id travels, as `zkd_i`. A
request too large to store is a local error, since echoing its `state` could make an unusable
redirect. Then:

- signed in already: straight on to consent or a code;
- otherwise the host's login page, or the one external provider directly when there is no local
  login, or `server_error` when neither is configured.

An interaction that ends in an error is deleted first, so a later sign-in cannot pick it up.

**After sign-in** (`InteractionOutcomes.ContinueAsync`) the client is looked up again, since it may
have been removed meanwhile. A client that does not require consent, on a request without
`prompt=consent`, gets its code now. Otherwise: `prompt=none` is answered `consent_required`; with no
consent page, a request that only asked is answered `consent_required` and a client that requires
consent is a logged `server_error`; else the user goes to the consent page. Consent is never
remembered.

**Issuing the code** (`AuthorizationCodeIssuer`). The scopes are what was requested, what the
registration allows now, and what the user granted. A registration that lost `openid` is answered
`invalid_scope` at the client. The interaction is claimed once only, so a double click, or Allow in
one tab and Deny in another, produces exactly one outcome. The code entry binds everything from the
stored interaction, never from the current request.

## The pages

`LoginInteraction`, `ConsentInteraction` and `ProviderSignInInteraction` share one shape: a read
for rendering, and terminal POST-only calls that write the redirect themselves. POST only, because
a call made while rendering a GET would decide every request on arrival.

- **Login:** the host verifies the credentials and passes a subject and how the user proved it. The
  framework writes the session; a consent decision from an earlier user on the same interaction is
  wiped. Under `prompt=login` or an outlived `max_age` the page is told so, and must have the user
  authenticate afresh rather than trust a cookie of its own.
- **Consent:** bound to the browser *and* to the session that signed in, so a different user cannot
  answer. A grant can only narrow what was requested and always includes `openid`. The page cannot
  be framed or cached.
- **External providers** are challenged after the optional `OnProviderChallenge` hook has had its say;
  under `prompt=login` or an outlived `max_age` only a hook answering `Reauthenticating` lets the
  challenge go, and otherwise the client gets `login_required`. They return to `/connect/resume`. The ticket must name this interaction and the
  provider that was challenged, and its principal must carry a subject with an issuer. The host's
  optional `OnProviderSignIn` hook gets that pair as `ExternalIdentity` and can let it through, park
  it for a host page, or deny. The subject is derived from the issuer and upstream `sub`, so
  equal ids at two issuers never meet. A parked sign-in finishes as the external user plus
  collected claims, or as a local account the page has proven the user owns; the upstream `sub` is
  refused as that account. Checks run before the parked ticket is taken, so a failed call does not
  use it up.
- **Deny** sends `access_denied`, plus a `zkd_error` naming the page for a client that opted in.

**Nothing to continue** (expired, completed, another browser, session changed, client removed) is
never thrown at the page. The user is sent to the client's `InitiateLoginUri` when it is known, else
to the error page.

## Binding to the browser

`zkd_i` travels in URLs, which leak. Each interaction also gets a random secret in a cookie,
`zkd.interaction.<id>`, and the store key and encryption are derived from id and secret, so another
browser cannot find or read it. At most 10 per browser. An ended interaction keeps a tombstone for a
day holding only an encrypted client id, which is how a late click finds its client.

**The SSO session is the `zkd.session` cookie** and nothing else: the user's claims plus `zkd:sid`,
`zkd:auth_time` and `zkd:amr`, encrypted, browser-session lifetime. Host-supplied `zkd:` claims are
stripped. The session id is kept when the same user signs in again. A missing `auth_time` fails
closed.

## What it costs

- The server cannot list or revoke sessions; sign-out clears one browser's cookie.
- Every client that requires consent asks every time, and fails `prompt=none`.

## What the walkthrough changed

The maintainer walked this part at code level. On the branch: a clearer name for the
`prompt=consent` check, and a registration that lost `openid` answered `invalid_scope` at the client
instead of on a local page. Filed: a null `ConsentPath` default (#954), and a server-side session
store with the cookie as a key (#955).

## What was rejected

- **Pre-routing interception through `IAuthenticationRequestHandler`.** It would hide the request
  from middleware for little protection, and need HTTPS, header and rate-limit handling rebuilt.
- **Requiring `nonce` on every `openid` request.** OIDC Core requires it only when the authorization
  endpoint returns an ID token, and the conformance suite refuses the stricter rule.
