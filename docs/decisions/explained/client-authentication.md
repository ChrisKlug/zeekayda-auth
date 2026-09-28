# Client authentication, explained

Explains the authentication half of `clients-and-client-authentication.md`: how the token endpoint
decides which client is calling, and how client secrets are stored and verified. Client registration
is explained separately; principles that apply beyond this part are in `principles.md`.

## What it is for

A confidential client proves who it is at the token endpoint. A failure never says why (RFC 6749
§5.2: a bare `invalid_client`), and never takes a different time depending on why, so response time
reveals neither which client ids exist nor whether a client is mid-rotation.

## The flow

**`CompositeClientAuthenticator`** runs every token request, top to bottom:

1. Cheap shape checks first: the form is read once, and more than one `Authorization` header is
   refused.
2. Every `IClientAuthenticator` is asked `CanHandle`. More than one match is refused, since RFC 6749
   §2.3 allows one method per request.
3. Only then is the client looked up, through the resolver from client registration.
4. No match means the `none` path, for public clients only.
5. The method must be one the authenticator declares, the server allows and the client allows.
6. The one matching authenticator verifies the credential.

**`ClientSecretAuthenticator`** is the built-in authenticator for `client_secret_basic` and
`client_secret_post`. It parses the credential and tries each stored secret; a client may hold two
during a rotation.

**`AuthenticatorCoverageValidator`** fails startup when a method the server advertises in discovery
has no authenticator, two authenticators claim one method, or one claims `none`.

## Secrets and hashers

**A stored secret is a hash**, never plaintext. `IClientSecretHasher` creates and verifies one
algorithm's hashes. PBKDF2-SHA256 at 600,000 iterations or more is built in and always registered;
a host may add others. **`CompositeClientSecretHasher`** dispatches each stored secret to its
hasher, creates new secrets with the default one, and holds the timing padding.

**Timing padding:** every failure costs the same as verifying two secrets with the default hasher.
It pads against a decoy that costs exactly what a real secret costs to verify.

## What it costs

- Every refusal path must remember to pad, and nothing in the structure enforces it yet.
- A hasher's safety rules (never throw, fixed-time compare) are documented, and enforced only for a
  hasher that uses the base class.

## Where it is going

The maintainer walked this part at code level. Each issue is in M1 before the security audit
(#537) unless marked, and updates this file when it lands.

**Authenticators**

- `CanHandle` returns a match with three states: not mine, mine with this method, or refused.
  "Basic and post at once" is refused, never treated as `none`. The chosen method travels to
  `AuthenticateAsync`, so the shape is decided once; the context drops `Headers`, and keeps
  `HttpContext` because mTLS needs the client certificate (#813).
- All padding lives in one public `VerifyAny` on the secret service, so a third-party authenticator
  gets the same timing guarantee and no caller counts. The service is renamed from
  `IClientSecretFactory` once it also verifies (#790). The `none` path drops the checks the resolver
  already guarantees and gets one refusal exit (#793).

**Secrets and hashers**

- A stored secret becomes one immutable, self-describing string in PHC form
  (`$pbkdf2-sha256$i=600000$<salt>$<hash>`), because a store package and a hasher package by
  different authors must compose. A hasher declares the algorithm ids it owns; a public `PhcString`
  helper formats and parses; samples show common hashing libraries and one that works in bytes.
  The per-algorithm types, `Snapshot` and `not_copied` go (#814).
- `IClientSecretHasher` is the one contract and its base class goes; the composite enforces its rules
  (dispatch by id, a failed verify for an exception, no whitespace secret).
  `GetRegistrationFailures` becomes `ValidateStoredSecret`, and the framework adds the client id to
  its messages (#814).
- Exactly one hasher creates new secrets. A host replaces PBKDF2 as the creator, which stays
  registered to verify existing secrets (#791).
- A host's PBKDF2 iteration count is currently dropped silently; it becomes a plain, validated option
  that refuses values outside 600,000–2,000,000 instead of clamping (#792).
- A pasted hash and a log entry for plaintext secrets (#806), and a `dotnet` tool creating hashes
  with the host's hasher (#807), stay in the First project milestone.

## What was rejected

- **A type per hashing algorithm**, which is easier for a hasher author, but a store cannot persist
  a type it has never heard of.
- **A hasher base class as the only contract.** It would be the one seam that is a class, and a
  subclass could still throw.
