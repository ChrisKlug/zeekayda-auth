# Token stores, explained

Explains `token-stores.md`: where authorization codes, refresh tokens and in-flight interactions
are kept, and how the framework keeps them single-use and safe at rest while a third party decides
where the bytes live. Principles that apply beyond this part are in `principles.md`.

## What it is for

An authorization code and a refresh token are bearer credentials. A code must be used exactly once;
a refresh token rotates on every use, and presenting a used one means it was stolen, so its whole
family is revoked (RFC 9700 §2.1.1, §2.2.2). Anyone who can read the database, a backup or a log
sidecar must not be able to use what they read (RFC 6819 §5.1.4.1.3).

## The shape: a framework store over a backing store

Each store is two layers.

- **The framework's store** (`AuthorizationCodeStore`, `RefreshTokenStore`, and three small
  interaction stores in AspNetCore) owns the protocol: single use, replay and reuse detection,
  hashing the handle before it becomes a key, encryption at rest, expiry with clock-skew grace.
- **The backing store** (`IAuthorizationCodeBackingStore`, `IRefreshTokenGrantStore`,
  `IInteractionBackingStore`) only keeps bytes. It receives keys as `StoreKey`, whose constructor
  only the framework can call, so it never sees a raw handle; values arrive already encrypted.

**Codes.** The backing store is a key-value primitive with one hard requirement: `TryInsertAsync`
is an atomic insert-if-absent. Redemption writes a tombstone through it; the one request that wins
the insert redeems the code, and every other request or later replay gets `AlreadyRedeemed` with the
family id, so the token endpoint can revoke everything the code produced. A client-id mismatch does
not consume the code, so a thief cannot burn it for its owner.

**Refresh tokens.** The backing store is a small row store: find by handle, mark consumed only if
still active (the one atomic step), revoke a family. Only the fields it must query on are in the
clear; everything else is encrypted by the framework. Decryption happens only after the atomic step
is won.

**Interactions** hold the state parked between redirects during a login: the original request, a
principal an external provider returned, a pending sign-out. They need nothing atomic.

**Registration.** Nothing is registered by default and a missing store fails startup. Development is
one line, `builder.AddInMemoryStores()`, which refuses to start outside `Development` unless the
call opts in. The TestKit ships conformance fixtures a store author runs against their backend.

## What it costs

- A production store needs a backend with a native atomic operation; a plain cache is not enough
  for codes or refresh tokens.
- Data Protection keys must be kept until every token they protected has expired; losing one logs
  users out silently.

## Where it is going

The maintainer walked this part at code level. The first three issues are in M1 before the security
audit (#537); the last two are in the First project milestone.

- **The framework's stores become internal classes (#827).** Their public interfaces and the hidden
  member that stopped anyone implementing them go; `InternalsVisibleTo` already lets AspNetCore use
  them. Every third-party contract ends in `BackingStore` (`IRefreshTokenGrantStore` →
  `IRefreshTokenBackingStore`), and all three stores use one key format,
  `zkd:{store}:{kind}:{hex(sha256)}`.
- **Two records get simpler (#828).** The code tombstone holds only the family id; its encrypted
  empty payload proved nothing. Revoking a family becomes an explicit record in the backing contract
  instead of a fake grant row planted in the third party's table.
- **The distributed-cache token stores are deleted (#829).** Without an atomic operation they cannot
  keep a code single-use on a shared cache; they were a production trap. The distributed-cache
  interaction store stays.
- **The interaction store becomes pluggable (#830),** with a public backing contract, a conformance
  fixture, and an optional keyed cache so ZeeKayDa's data need not share the host's cache. The
  Cosmos store (#805) is its first user.
- **A host can revoke every refresh token for a user (#831).** The backing contract already requires
  it; the host API gives it a caller, and production stores design the subject index in from the start.
- TestKit polish (reporting skipped tests as skipped, docs, test-framework support) waits until after M1.

## What was rejected

- **Plain `I…Store` names for the backing contracts.** `class AuthorizationCodeStore` would read as
  implementing `IAuthorizationCodeStore` while it wraps it.
- **Verifying the tombstone's encrypted payload** instead of deleting it: an attacker who can write
  to the store can do far worse than forge a tombstone.
- **In-memory stores registered by default.** A host that forgot a real store would run on one; the
  explicit line documents the choice and the missing store fails loudly.
