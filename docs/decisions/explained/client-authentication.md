# Client authentication, explained

Explains the authentication half of `clients-and-client-authentication.md`: how the token endpoint
decides which client is calling, and how client secrets are stored and verified. Client registration
is explained separately; principles that apply beyond this part are in `principles.md`.

## What it is for

A confidential client proves who it is at the token endpoint. A failure never says why (RFC 6749
§5.2: a bare `invalid_client`), and every refusal that touches a client takes the same time, so
response time reveals neither which client ids exist nor whether a client is mid-rotation.

## The flow

**`CompositeClientAuthenticator`** runs every token request, top to bottom:

1. Cheap shape checks first: the form is read once, and more than one `Authorization` header is
   refused.
2. Every `IClientAuthenticator` is asked `CanHandle`, which answers not mine, mine for one method,
   or refused. A refusal is refused, never treated as `none`, and so is more than one match, since
   RFC 6749 §2.3 allows one method per request. A `CanHandle` that throws counts as not mine.
3. Only then is the client looked up, through the resolver from client registration.
4. No match means the `none` path, for public clients only, with one refusal exit.
5. The method must be one the authenticator declares, the server advertises and the client allows.
6. The one matching authenticator verifies the credential for the method it matched. A throw counts
   as a padded refusal.

**`ClientSecretAuthenticator`** is the built-in authenticator for `client_secret_basic` and
`client_secret_post`. It reads the presented secret and passes it, with the client's stored secrets,
to `ClientSecrets.Verify`; a client may hold two during a rotation.

**What the server advertises** is what its authenticators declare, plus `none`, narrowed by
`TokenEndpoint.AdvertisedAuthMethods`. Startup fails when two authenticators declare one method, one
declares `none`, a method name is malformed, or the filter leaves nothing to advertise.

## Secrets and hashers

**A stored secret is a hash**, never plaintext: one self-describing string in PHC form
(`$pbkdf2-sha256$i=600000$<salt>$<hash>`), so a store package and a hasher package by different
authors compose. `IClientSecretHasher` creates and verifies hashes for the algorithm ids it declares,
and `PhcString` formats and parses. PBKDF2-SHA256 at 600,000 to 2,000,000 iterations is built in and
always registered. A host may add others and make one the default for new secrets; PBKDF2 stays
registered to verify existing ones.

**`ClientSecrets`** creates new secrets with the default hasher and verifies a presented secret
against the stored ones, each sent to the hasher that declared its algorithm id. The registry behind
it indexes the hashers at startup, and fails startup on a duplicate or missing id or two defaults.

**Timing padding:** every failure costs two verifications by every registered hasher, each against
a decoy of its own that costs exactly what a real secret does. A failed `Verify` returns one-time
proof that it already padded, so an authenticator never counts.

## What it costs

- Inside the composite, each refusal exit still calls the padding by hand.
- Of a hasher's safety rules, only the fixed-time compare is left to the hasher; the framework
  enforces the rest for every hasher (a throw is a mismatch, blank input never reaches `Create`, an
  undeclared id is refused).

## What the walkthrough changed

The maintainer walked this part at code level. What it decided has landed in M1: the three-state
`CanHandle` with the method carried to `AuthenticateAsync` (#813), padding owned by `ClientSecrets`
(#790), one refusal exit on the `none` path (#793), PHC-string secrets and the one hasher contract
(#814), a host default hasher (#791), and a validated PBKDF2 iteration count (#792).

Still open, in the First project milestone: a log entry when a plaintext secret is used (#806), and
a `dotnet` tool creating hashes with the host's hasher (#807).

## What was rejected

- **A type per hashing algorithm**, which is easier for a hasher author, but a store cannot persist
  a type it has never heard of.
- **A hasher base class as the only contract.** It would be the one seam that is a class, and a
  subclass could still throw.
