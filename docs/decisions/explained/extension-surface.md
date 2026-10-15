# The extension surface, explained

Explains `extension-surface.md`: what a third party may implement, what it may only consume, and the
shape the seams share. Each seam's own rules were walked in its own part; this part looked at them
side by side. Principles that apply beyond this part are in `principles.md`.

## The house pattern

Where a subsystem has a protocol to enforce and a genuinely variable part, the variable part is a
public interface and the protocol is a type a third party cannot stand in for:

- `ISigningKeySource` is implementable; the `SigningKeyRing` it feeds is sealed with an internal
  constructor, so nothing skips key validation or the signer self-test.
- A backing store stores encrypted bytes under an opaque `StoreKey` it cannot construct; the
  coordinator above it owns single use, encryption and expiry.
- `SanitizingLogger<T>` can be injected everywhere and constructed nowhere outside the framework.
- The interaction services are sealed classes only the framework builds.

The wrong thing is made impossible rather than forbidden.

## The seams

| Seam | Role | Registered with |
|---|---|---|
| `IClaimsProvider` | the user's claims; required | `AddClaimsProvider<T>()` |
| `ISigningKeySource`, `ISigner` | lists keys, lends signers | `AddSigningKeySource<T>()` and provider helpers |
| `IAuthorizationCodeBackingStore` | code storage | `AddAuthorizationCodeStore<T>()` |
| `IRefreshTokenBackingStore` | refresh token storage | `AddRefreshTokenStore<T>()` |
| `IClientAuthenticator` | client authentication methods | `AddClientAuthenticator<T>()` |
| `IClientSecretHasher` | secret hashing | `AddClientSecretHasher<T>()` |
| `OnProviderSignIn` | hook after an external sign-in | `WithProviders(…)` |
| options of a package's own | validated with the framework's | `AddZeeKayDaOptions<T>()` |
| `IClientRepository`, `IScopeRepository` | clients, scopes | raw DI today |
| `IStartupVerifier`, `IStartupActivator` | startup checks | raw DI today |

**Naming.** A *Repository* is domain data the host owns, looked up read-only (clients, scopes). A
*BackingStore* is dumb encrypted bytes under a framework coordinator that owns the protocol (codes,
refresh tokens). A *Source* lists data that lives elsewhere (signing keys in a vault or a file).
Three contracts, three names.

**`IClaimsProvider`** is the one seam every host implements. It is told the subject, the scopes and
the claim types that will be kept, which is a fetch hint, not a rule: the framework filters
whatever comes back. A claim it does not return is left out; a repeated single-valued claim, values
that cannot be merged, or a throw is `server_error` with nothing issued. The client is not passed,
since claims belong to the user and what each client sees is the framework's selection.

## What it costs

- Half the seams are registered through raw DI, so setup is not one fluent chain and registration
  order matters in places.

## What the walkthrough changed

The maintainer walked this part at code level, seam by seam. Decided, to be filed at triage:

- **Every seam is registered through the builder**, including the repositories and startup checks.
- **`IClientRegistrationValidator` stops being implementable.** It meant two things: "validate this
  client" (what a repository resolves) and "add my rules" (what a host registers, which then
  replaced the first). It becomes a framework class a repository may call before saving; host rules
  are dropped, since a host can check its clients where it defines them.
- **`ITokenIssuer` becomes internal.** Userinfo accepts only JWTs this server signed, there is no
  introspection, and the ID token must be a JWT anyway, so no replacement could work. Reference
  tokens are designed with the refresh token work (#539).
- **`IDiscoveryDocumentProvider` becomes internal.** A replacement could advertise what the server
  does not do. Extra metadata fields, if needed, come through an additive seam that cannot override
  the computed ones.

Kept: the three seam names, and claim types as a hint. Test users from configuration stay in
v1.0.0 (#786).

## What was rejected

- **A third-party-implementable store protocol.** It let an implementer break single use while
  compiling; the reversal produced the house pattern.
- **Interaction services as public interfaces.** A swap left each protocol step guarded only by a
  startup check.
- **A friend grant instead of public contracts.** It serves one first-party package and never a
  third party.
