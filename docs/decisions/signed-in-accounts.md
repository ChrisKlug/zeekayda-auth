# Signed-in accounts

**Built.** What the SSO session cookie holds, which of its accounts answers a request, and how
accounts join and leave it. The interaction surface around it is `interaction-and-session.md`; the
authorize endpoint's protocol rules are `authorization-and-interaction.md`; end-session is
`endpoints.md`.

## Decisions in force

**Authentication is per browser; the account that answers is chosen per request.** `zkd.session`
holds a list of accounts, each with its own session identifier, `auth_time`, sign-in time, methods and
optional login identifier, so single sign-on across clients is unchanged and one browser can be signed in as
several users — the same app in two tabs, each refreshing silently with its own `id_token_hint`, is
the case it exists for. A session per client was rejected: it is no single sign-on at all.

**An account's session identifier is framework-minted, unguessable and stable for the life of that
account's session — and is not the cookie value, which is regenerated on every write so that
session-fixation resistance is a stated property rather than an accident of what `SignInAsync` does
today.** It is carried as a reserved claim the host neither supplies nor sees and kept across
re-authentication of the same subject (`prompt=login` and `max_age` refresh its times, never its identifier); a
subject the browser does not hold gets a new one. One derived from the cookie value breaks every
binding the moment the cookie rotates, and one tracking authentication events could never key a
denylist. Per account the cookie holds exactly what its one reader takes — `sub`, `zkd:sid`,
`zkd:auth_time`, `zkd:signed_in`, `zkd:amr`, and `zkd:login_id` when the sign-in gave one — plus one `zkd:client`
claim per remembered client; pages pass a subject and methods, never claims, and promotion copies no
provider claim. A host's subject is 1–255 characters, each 0x21–0x7E (OIDC Core §2 caps `sub` at 255
ASCII), refused at the call: a subject is compared exactly, so a stray space would make two users.

**Each account lives for the cookie lifetime from its own last sign-in; `auth_time` is a second clock.**
A page may sign in from an earlier authentication, such as a cookie of the host's own, and pass when
it happened as `authenticatedAt` (capped at now): that is `auth_time`, which `max_age` and the ID
token read (OIDC Core §3.1.2.1), while the account's life runs from the sign-in. A sign-in whose
`authenticatedAt` was already older than the request's own `max_age` when the request was made, or
under `prompt=login` earlier than the request, is refused at the page before anything is consumed;
`max_age=0` is `prompt=login`. One shared clock was rejected: an old
`authenticatedAt` would sign the user in already expired. A write for another
account, a choice or a sign-out never lengthens any account's life: the ticket expires with the most
recently signed-in account, and an account past its own lifetime is dropped on read.

**The account that answers: the one an `id_token_hint` names, else the one a `login_hint` names,
else the client's own.** A hint naming no account here means that user must sign in — the login page
(with `LoginRequest.RequiredSubject` or the hint pre-filled), `login_required` under `prompt=none` —
never another account answering silently: a client that named bob and got alice is the cross-account
mix-up this design removes. A verified `id_token_hint` wins over a `login_hint`. A `login_hint`
matches a login identifier ignoring case, as an email is typed, or a subject exactly; with no login
identifier the subject stands in, so a host that passes none never matches a client's email hints,
and its `LoginIdentifier` docs say so. A client's own account is the one last signed in to or
picked for it, else the most recently signed-in, remembered per client, capped and least recent first
out. Only a sign-in or a picker choice writes the cookie; a silent answer never does. `prompt=login` and `max_age` are judged against the account that answers, not the whole cookie.

**A sign-in replaces the accounts held unless the page asks to add.** `SignInAsync` signs every
other account out — the safe default on a shared computer, where the previous user would otherwise
stay signed in unseen — and `AddAccountAsync` keeps them; the page decides when, asking the user or
always adding, and the framework never infers it. External sign-ins decide in `OnProviderSignIn`
through `ProviderSignInContext.AddAccount` and `.LoginIdentifier`, carried with a parked principal to
the linking page, whose `SignInWithReplacedAccountAsync` identifier wins; with no hook an external
sign-in replaces. A browser holds at most `MaxSignedInAccounts` (default 5, refused above 20, where the cookie nears
header limits); adding past it signs
out the account least recently signed in to or chosen — the direction that only ever removes access.
A login identifier is held to the `login_hint` rule it is matched against.

**The account picker is its own page, and the framework decides when it is shown.** Only
`prompt=select_account` sends the browser to `SelectAccountPath`, and only when an account it holds
could answer without signing in again — the hinted user's, within `max_age`, none under
`prompt=login`; otherwise the login page. Without a picker the answer stays
`account_selection_required` (OIDC Core §3.1.2.6). `AccountSelectionInteraction.SelectAsync`
re-checks the choice against the cookie when posted, so a forged or stale subject is refused, and a
picker reached for any other request has nothing to continue. Folding the picker into the login page
was rejected: every host would have to re-implement when picking is allowed.

**The provider challenge hook is told the hinted subject.** `ProviderChallengeContext.RequiredSubject`
lets a host steer the provider — its own `login_hint`, or `prompt=select_account` — since the derived
subject cannot be sent upstream; the completion check stays the safety net, refusing a return as
anyone else with `login_required`.

**Logout ends one account unless the page ends all.** A valid `id_token_hint` ends only the account it
names. Without one, or with one for a user not signed in here (RP-Initiated Logout §2 requires asking),
the logout page is asked about the client's own account and gets every account as
`LogoutRequest.SignedInAccounts`; `SignOutAllAsync` ends whatever remains, even once the asked
account is gone, and the framework's own confirmation page offers it too. Any sign-out ends every interaction the browser has in flight.
Which relying parties are told is unbuilt.

## Tried, didn't work

- **A silent answer remembering its account for the client.** Every hint-selected refresh rewrote the
  cookie, and one read before a sign-out wrote the signed-out account back.
