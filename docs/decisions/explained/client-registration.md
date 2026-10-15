# Client registration, explained

Explains the registration half of `clients-and-client-authentication.md`: what a client is, how it
is defined, checked, stored and looked up. Client authentication is explained separately; principles
that apply beyond this part are in `principles.md`.

## What a client is

Two interfaces. `IClient` is everything a client may do: redirect URIs, scopes, grant types,
whether consent and PKCE are required, lifetimes, claim additions. `IClientWithCredentials` adds its
**credentials**, the stored `Secrets`. Code that decides what to issue a client only ever gets the
first, so it never sees secrets. A custom repository can make its own database entity implement them
directly. Every member except `ClientId` and `Secrets` defaults to the safe answer from one
`ClientDefaults` source (consent and PKCE required, lifetimes the server's), so a custom entity
implements `ClientId`, `Secrets` and what it stores.

## How clients are registered

- **`Client`** is the framework's sealed record, a plain data carrier with safe defaults, plus
  `CreateConfidential` (taking an already hashed `ClientSecret`) and `CreatePublic`.
- **`AddInMemoryClients(c => …)`** offers `AddPublic`, `AddConfidential` and `Add(client)`. A
  confidential client sets exactly one of `Secret` (plaintext, hashed at startup) or `SecretHash`
  (stored as given). An overload binds the same options from configuration, keyed by client id.
- **`IClientRepository`** has one read-only method, `FindByClientIdAsync`. It returns `null` for an
  unknown client; a repository that throws is a server error. Dynamic registration (RFC 7591) is out
  of scope for v1.

## How clients are checked

**`ClientRegistrationValidator`** holds the rules: exact redirect-URI matching; public ⇔ no secret ⇔
the only auth method is `none` (`IsPublic` is declared, never derived); PKCE opt-out only where safe;
at most two secrets; auth methods the server actually advertises; a client may narrow the server's
allowlists (grant types, auth methods, signing algorithms), never widen them. Token lifetimes are
different: a client's override replaces the server default and has no upper bound. It returns its failures, each with a stable code. A host may add its own
`IClientRegistrationValidator`, which runs after the framework's rules and can add rules but never
remove them.

**`ValidatedClientResolver`** is the only way from a `client_id` to a client. It refuses a malformed
`client_id` before the repository sees it, copies what the repository returned into a snapshot so a
database entity cannot change after it was checked, validates the copy on every lookup, and returns
it without credentials (`FindClientAsync`) or, for client authentication only, with them
(`FindClientWithCredentialsAsync`). A failing client is served as unknown and logged once per
distinct failure. A custom repository gets the same checks as the built-in one without doing
anything. This is the pattern of making third-party output safe one layer below the code that uses
it.

**The in-memory repository** is built at startup: it hashes plaintext secrets, rejects duplicate
ids, validates every client, checks their scopes exist, and fails startup with every problem at once.
A host with no repository at all fails startup too.

## What it costs

- A client property is added in about six places: `IClient`, `ClientDefaults`, the `Client` record,
  `ClientOptions`, the snapshot, and usually the validator.
- Validation runs on every lookup. It stays cheap because checking a stored secret only parses it and
  never derives a hash.

## What the walkthrough changed

The maintainer walked this part twice, the second time at code level. What it decided has landed in
M1: the `IClient` / `IClientWithCredentials` / `Client` names and the resolver split (#809), one
`ClientDefaults` source (#810), the collection convention (#774), a validator that returns its
failures and a named `Build` step (#811, #797), no empty-secret probe, fingerprint or verdict cache
(#788, #790), no `ZEEKAYDA0003` analyzer (#787), one bindable options shape (#780), `zkd_error`
(#789), and self-describing secret strings (#814).

Still open, in the First project milestone and closed by its own security review (#808): a log entry
when a plaintext secret is used (#806; `SecretHash` itself has landed), and a `dotnet` tool creating
the hash with the host's own hasher (#807).
