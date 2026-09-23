# The usage API, explained

What a host writes to run an identity provider, read from the sample host. There is no register
file of its own; each call leads into a subsystem explained elsewhere.

## `Program.cs`

1. **`AddZeeKayDaAuth(options => …)`** returns the builder. `Issuer` is required. The options also
   point the framework at the host's own pages: login, consent, error, logout, signed-out.
2. **`AddInMemoryScopes(…)`** replaces the default scope set, `StandardScopes.All`. Most hosts never
   call it.
3. **`AddInMemoryClients(c => c.AddConfidential(…) / c.AddPublic(…))`** registers the applications
   allowed to sign users in.
4. **`AddInMemoryStores()`** (or the distributed-cache stores) decides where authorization codes,
   refresh tokens and interaction state live. The in-memory stores refuse to start outside
   `Development` unless explicitly allowed.
5. **A signing key**: a PEM or PFX file, Azure Key Vault, the Windows certificate store, or the
   development keys.
6. **`AddClaimsProvider<T>()`** registers the one interface every host must implement: given a
   subject, return its claims, or say the subject is no longer valid.
7. **`app.MapZeeKayDaAuth()`** maps discovery, authorize, token, JWKS, userinfo and end-session.

If a required step is missing, startup fails and names it (the presence checks in
`options-and-startup-verification.md`).

## The pages

The host owns the UI; the framework owns the protocol. Each page injects one interaction service:
`ILoginInteraction`, `IConsentInteraction`, `ILogoutInteraction`, `IErrorInteraction`, and
`IProviderSignInInteraction` for completing an external sign-in.

Sign-in, deny, grant and sign-out are **terminal** calls: they write the HTTP response themselves,
normally a redirect back to the client. The page handler just returns, and the framework skips
rendering the page. A page never touches a return URL, a cookie or an authentication scheme. That is
the point of the interaction services: it should be obvious what each page has to do.

A page path left at `null` has a meaning:

- **Login:** when local sign-in is off and exactly one external provider is registered, the
  framework goes straight to that provider.
- **Error and signed-out:** the framework renders a minimal, unbranded page of its own.
- **Consent:** only clients that require consent need it.

A host with one external provider and consent off needs no pages at all.

## What it costs

- A working host needs seven calls, and each one is a separate decision for a newcomer.
- Configuring a client for anything past the defaults means knowing two places: the client, and the
  server-wide list of allowed authentication methods.

## What the walkthrough changed

Each item below is an M1 issue, done before the security audit (#537), unless noted otherwise. When one
lands, this file is updated to match.

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
- #786 (v1.0.0, not M1): a working development IdP from one configuration section and one line.
