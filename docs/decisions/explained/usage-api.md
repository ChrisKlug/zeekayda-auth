# The usage API, explained

What a host writes to run an identity provider, read from the sample host. There is no register
file of its own; each call leads into a subsystem explained elsewhere.

## `Program.cs`

1. **`AddZeeKayDaAuth(issuer)`**, or an overload taking a configuration section or an options
   delegate, returns a `ZeeKayDaAuthBuilder`. `Issuer` is required. The options also point the
   framework at the host's own pages: login, consent, error, logout, signed-out.
2. **`AddInMemoryScopes(…)`** replaces the default scope set, `StandardScopes.All`. Most hosts never
   call it.
3. **`AddInMemoryClients(…)`** registers the applications allowed to sign users in, from a
   configuration section keyed by client id or with `c.AddConfidential(…)` / `c.AddPublic(…)`.
4. **`AddInMemoryStores()`** decides where authorization codes, refresh tokens and interaction state
   live, and refuses to start outside `Development` unless explicitly allowed. In production a host
   registers its own code and refresh token stores, and `AddDistributedCacheInteractionStore()`.
5. **A signing key**: a PEM or PFX file, Azure Key Vault, the Windows certificate store, or the
   development keys.
6. **`AddClaimsProvider<T>()`** registers the one interface every host must implement: given a
   subject, return its claims, or say the subject is no longer valid.
7. **`app.MapZeeKayDaAuth()`** maps discovery, authorize, token, JWKS, userinfo and end-session,
   plus the provider callback and `/connect/resume` once external providers are registered.

If a required step is missing, startup fails and names it (the presence checks in
`options-and-startup-verification.md`).

## The pages

The host owns the UI; the framework owns the protocol. Each page injects one interaction service:
`LoginInteraction`, `ConsentInteraction`, `LogoutInteraction`, `ErrorInteraction`, and
`ProviderSignInInteraction` for completing an external sign-in. They are sealed classes only the
framework builds.

Sign-in, deny, grant and sign-out are **terminal** calls: they write the HTTP response themselves,
normally a redirect back to the client. The page handler just returns, and the framework skips
rendering the page. A page never touches a return URL, a cookie or an authentication scheme. That is
the point of the interaction services: it should be obvious what each page has to do.

Whether a page is needed is decided before its path is ever read, so a path is only an address:

- **Login:** when local sign-in is off and exactly one external provider is registered, the
  framework goes straight to that provider and never visits the login page.
- **Consent:** only clients that require consent, or requests with `prompt=consent`, reach it.
- **Error and signed-out:** with no path, the framework renders a minimal, unbranded page of its own.

Because the paths are only addresses, login and consent default to `/login` and `/consent`, which
also gives a future UI package fixed addresses to serve. A host with one external provider and
consent off needs no pages at all, provided it sets `ConsentPath` to null: otherwise a
`prompt=consent` request is sent to a consent page that does not exist.

## What it costs

- A working host needs six calls (scopes are optional), and each one is a separate decision for a
  newcomer.

## What the walkthrough changed

Every item below landed in M1 except #786, which is in v1.0.0.

- #777: the basic sample is split from the conformance-suite host, and shows only the minimum.
- #778: the advertised token-endpoint auth methods are derived from the registered authenticators,
  so a public client needs no server-wide setting.
- #779: a client's allowed auth methods get the default only when the host names none.
- #780: clients are registered with one options shape and can be bound from configuration.
- #781: `SignInAsync` takes a subject and optional extra claims, not a hand-built principal.
- #782: every interaction service, login included, offers the same curated view of the request.
- #783: a small set of host-facing namespaces, with feature namespaces beneath.
- #784: `Task`, not `ValueTask`, throughout the public API.
- #785: an `AddZeeKayDaAuth(issuer)` overload, and default login and consent paths.
- #786: a working development IdP from one configuration section and one line.
