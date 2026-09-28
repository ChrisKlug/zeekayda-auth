# Client registration, explained

Explains the registration half of `clients-and-client-authentication.md`: what a client is, how it
is defined, checked, stored and looked up. Client authentication is explained separately; principles
that apply beyond this part are in `principles.md`.

## What a client is

Two interfaces. `IClientMetadata` is everything a client may do: redirect URIs, scopes, grant types,
whether consent and PKCE are required, lifetimes, claim additions. `IClientRegistration` adds its
**credentials**. Code that decides what to issue a client only ever gets the first, so it never sees
secrets. A custom repository can make its own database entity implement them directly. Optional
members default only where the default is the safe answer: consent and PKCE required, lifetimes the
server's.

## How clients are registered

- **`ClientRegistration`** is the framework's sealed record, a plain data carrier with safe
  defaults, plus `CreateConfidential` and `CreatePublic` for the two kinds.
- **`AddInMemoryClients(c => …)`** offers `AddPublic`, `AddConfidential` (a plaintext secret, hashed
  at startup) and `Add(registration)`.
- **`IClientRepository`** has one read-only method, `FindByClientIdAsync`. It returns `null` for an
  unknown client. Dynamic registration (RFC 7591) is out of scope for v1.

## How clients are checked

**`ClientRegistrationValidator`** holds the rules: exact redirect-URI matching; public ⇔ no secret ⇔
the only auth method is `none` (`IsPublic` is declared, never derived); PKCE opt-out only where safe;
a client may narrow the server's settings, never widen them. Every failure carries a stable code.

**`ValidatedClientResolver`** is the only way from a `client_id` to a client. It copies what the
repository returned into a snapshot, so a database entity cannot change after it was checked,
validates the copy, and returns it. A failing client is served as unknown and logged once. A custom
repository gets the same checks as the built-in one without doing anything. This is the pattern of
making third-party output safe one layer below the code that uses it.

**The in-memory repository** hashes the plaintext secrets, rejects duplicate ids, validates every
client, and fails startup with every problem at once.

## What it costs

- A client property is added in about six places: the interface, the record, `ClientOptions`, the
  snapshot, the fingerprint, and usually the validator.
- The resolver caches validation verdicts, because validating a confidential client runs a full
  PBKDF2 verification per secret (the check that no secret accepts an empty password).

## Where it is going

The maintainer walked this part twice, the second time at code level. Each issue is in M1 before the
security audit (#537) unless marked, and updates this file when it lands.

**The contract**

- `IClientMetadata` becomes `IClient`, `IClientRegistration` becomes `IClientWithCredentials`, and
  the record becomes `Client`. The resolver splits: `FindClientAsync` returns `IClient`, and only
  client authentication gets the credentials (#809).
- Every member except `ClientId` gets a safe default from one `ClientDefaults` source, so a custom
  entity implements `ClientId` plus what it stores (#810). `AllowedResponseTypes` and
  `AllowedResponseModes` stay, because more values are coming.
- Collections follow one convention: sets for client string lists, `IReadOnlyList` for returned
  collections (#774).

**Checking and lookup**

- The validator returns its failures instead of throwing, with its rules in a logical order; the
  in-memory repository gets a named `Build` step instead of a 70-line constructor (#811, #797).
- The verify path refuses empty secrets itself, so the expensive probe, the fingerprint and the
  verdict cache go; the resolver refuses a malformed `client_id` before the repository sees it, and a
  repository outage stays a server error (#788, #790).
- Analyzer `ZEEKAYDA0003` and the repository's "MUST validate" doc paragraphs go: the resolver
  already does it (#787).
- `ClientOptions` collapses into one configuration shape, bindable from configuration (#780).
- `zkd_error` gets built: the per-client flag exists, but nothing emits the field (#789).

**Secrets** (First project milestone, closed by its own security review, #808)

- A pasteable, self-describing hashed-secret string, accepted alongside plaintext, with a log entry
  when plaintext is used (#806).
- A `dotnet` tool that creates the hash with the host's own configured hasher (#807).
