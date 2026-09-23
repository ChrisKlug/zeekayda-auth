# Client registration, explained

Explains the registration half of `clients-and-client-authentication.md`: what a client is, how it
is defined, checked, stored and looked up. How a client proves who it is at the token endpoint is
explained separately.

## What a client is

Two interfaces. **`IClientMetadata`** is what a client may do: redirect URIs, scopes, grant types,
whether consent and PKCE are required, token lifetimes, claim additions. **`IClientRegistration`**
adds its **credentials**. The split means the code that decides what to issue a client, token
issuance above all, never receives its secrets; only client authentication does.

A custom repository can make its own database entity implement the interfaces directly, so a lookup
needs no mapping object. Optional members have default implementations only where the default is
the safe answer: consent and PKCE default to required, and lifetimes default to the server's.

## How clients are registered

- **`ClientRegistration`** is the framework's sealed record. Its defaults: code grant, PKCE
  required, consent required, `client_secret_basic`.
- **`AddInMemoryClients(c => …)`** offers `AddPublic`, `AddConfidential` (a plaintext secret, hashed
  when the repository is built) and `Add(registration)`, each with a `ClientOptions` callback for
  the rest.
- **`IClientRepository`** has one method, `FindByClientIdAsync`. It returns `null` for an unknown
  client and never throws, so timing and exceptions reveal nothing about which ids exist. It is
  read-only: dynamic registration (RFC 7591) is out of scope for v1.

## How clients are checked

**`ClientRegistrationValidator`** holds the rules:

- Redirect URIs match exactly, with no wildcards: `https` anywhere, `http` on loopback only, and
  private schemes only if they contain a dot (native apps).
- Public ⇔ no secret ⇔ the only auth method is `none`. `IsPublic` is declared, never derived, so an
  omission fails instead of silently changing security behaviour.
- PKCE opt-out is allowed only where it is safe.
- A client can only narrow the server's settings (signing algorithms, lifetimes, scopes), never
  widen them.

**`ValidatedClientResolver`** is the only way from a `client_id` to a client. It copies what the
repository returned into a snapshot, so a database entity cannot change after it was checked, then
validates the copy and returns it. A failing client is treated as unknown and logged once. A custom
repository gets the same checks as the built-in one without doing anything.

**The in-memory repository** also validates everything at startup, together with duplicate ids and
secret hashing, and reports every failure at once.

## What it costs

- A new client property is added in about six places: the interface, the record, `ClientOptions`,
  the snapshot, the fingerprint, and usually the validator.
- The resolver is 346 lines, about half of it a verdict cache.

## What the walkthrough changed

M1 issues, done before the security audit (#537). When one lands, this file is updated to match.

- #780 also collapses `ClientOptions`, which copies `ClientRegistration` member by member twice.
- #787: delete analyzer `ZEEKAYDA0003`. It dates from before the resolver validated what it serves.
- #788: validate on every lookup and delete the fingerprint verdict cache. Validation costs
  microseconds, next to a PBKDF2 verification thousands of times dearer.
- #789: build `zkd_error`. `EnableZkdErrorCodes` exists per client, but nothing emits the field. It
  lets a client tell "the user cancelled" from "sign-in failed" without revealing anything the user
  does not already know.
- #778 also removes the in-memory repository's "`none` advertised but no public client" warning.
