# Clients and client authentication

Client registration, credentials, and how the token endpoint decides which client is calling.
Implementing a repository is `docs/reference/client-secrets.md` and
`docs/how-to/implement-custom-client-repository.md`.

## Decisions in force

**Clients are statically registered.** RFC 7591 dynamic registration is not in v1: it materially
widens the attack surface of a static-first framework. The v1 abstractions are shaped so a write-side
package can decorate them later without a breaking change.

**A client registration is a pair of interfaces, not a sealed shape.** A custom repository makes its
own ORM entity implement them directly, so lookup on the token endpoint's hot path allocates no
mapping object. `IClientMetadata` carries everything except the credentials and `IClientRegistration`
adds them, so code deciding *what* to issue a client — token issuance above all — never receives its
secrets; only client authentication takes `IClientRegistration`. The inheritance means a downcast
still reaches them, which is the point: a guardrail against accidental use, not a boundary against a
determined caller, who could resolve the repository anyway. The framework ships a sealed record implementation for hosts that want one, and validation
lives in a separate validator rather than in a constructor, so a test can construct an invalid
registration deliberately.

**Every string set on a registration MUST be compared with explicit `StringComparer.Ordinal`.** The
set's own comparer is not trusted — a custom repository's entity type is free to build one with
`OrdinalIgnoreCase`, which would silently widen a redirect-URI or auth-method allowlist.

**`IsPublic` is declared, never derived, and the three-way consistency rule is enforced at
registration:** public ⇔ no credentials ⇔ auth methods are exactly `{ "none" }`. A default
interface method computing it would let a configuration omission quietly change security behaviour
instead of failing a startup check. Exactly one member on the interface *is* a default interface
method — the per-client signing-algorithm allowlist, where `null` means "inherit the server default"
and there is no security-relevant thing to omit.

**Credential type identity is the algorithm; there is no string discriminator and no
`string? ClientSecret`.** A bare string is ambiguous about plaintext versus hash and pushes fixed-time
comparison onto every implementer; a single `Algorithm` discriminator with nullable per-algorithm
fields grows a central switch statement unboundedly. Adding bcrypt means defining a credential
sub-interface and a paired hasher — no framework change.

**Verification is always fixed-time and never throws.** A hasher returns `false` on internal error
rather than propagating, so an exception cannot become a timing or behavioural oracle. The shipped
default is PBKDF2-HMAC-SHA256 with a 600,000-iteration floor (current OWASP guidance), enforced both
where a credential is created and where a pre-hashed one is imported — a credential migrated from
another IdP bypasses the constructor entirely, so the import check is the only thing standing between
a weak stored hash and production. At most two active shared secrets per client, to make rotation
possible; authenticators try both before failing.

**Failure paths are padded to a fixed two-credential budget; the success path is not.** The composite
hasher pre-computes a dummy credential with the default hasher at host startup — roughly 600 ms paid
once — and burns exactly that budget on every path that has no real credentials to verify: unknown
client, method not in the server allowlist, method not in the client's allowlist, and every `none`
rejection. It also pads a failure from a non-default hasher, so a faster custom hasher cannot reopen
the oracle. A client mid-rotation is therefore not timing-distinguishable from an unknown one, and
"public client rejected" is not distinguishable from "no such client". Successful `none`
authentication is deliberately *not* padded: the outcome is already visible in the HTTP response and
`client_id` is not a secret in OAuth. Client-ID enumeration by request volume is out of scope for the
timing design — rate limiting is the primary mitigation (RFC 9700 §2.1).

**The composite hasher is registered as its own concrete type, never as the hasher interface.**
Registering it under the interface would let it be injected into its own `IEnumerable<>` dependency
and recurse on the first verification. Multiple registered hashers require one explicit default;
ambiguity is a startup failure, not a silent pick.

**Authenticators are self-describing; the composite has zero method-specific knowledge.** Each
authenticator declares the method strings it owns and detects its own request shape, so adding mTLS
means implementing, registering, and adding the method string to the server allowlist — the composite
never changes. Startup validation requires every advertised server method to have exactly one owning
authenticator. `none` must never be declared by any authenticator: it is the composite's fallback
after every credential-bearing authenticator has declined, because a generic "no evidence"
authenticator cannot know about custom mechanisms and would collide with them.

**The composite defends against its own extension point.** More than one matching authenticator is
`invalid_client` (RFC 6749 §2.3). An exception thrown from a shape check is logged and treated as
non-matching rather than failing the request. A returned method not in the authenticator's own
declared set is rejected — otherwise a buggy detector could route past the startup coverage check.
Repository lookup is deferred until after the cheap rejections, so an ambiguous request costs no I/O.

**Redirect URI matching is exact and ordinal — no prefix, normalisation or wildcard.** `http` is
accepted only for loopback, where the port varies (RFC 8252 §7.3); the loopback test is a whole-string
match so `localhost.attacker.com` fails. Fragments, userinfo and path traversal are rejected, the URI
count is capped, and the scheme rule is a **pure allowlist** — `https` on any host, `http` on
loopback, and any private-use scheme containing a dot (RFC 8252 §7.1). No blocklist is maintained,
because every dangerous scheme (`javascript`, `data`, `file`) lacks a dot and the allowlist rejects it
without being told about it. A `localhost` host logs an advisory warning recommending the IP literal
(RFC 8252 §8.3). Post-logout redirect URIs get the same treatment.

**A registration whose credential no registered hasher can handle is a startup failure, and so is one
whose credential accepts an empty presented secret.** Both would otherwise surface at runtime as an
ordinary `invalid_client`, indistinguishable from a wrong password — or, for the empty-secret case,
as unauthenticated access.

**Client lookup returns `null` for unknown or malformed ids and never throws.** Throwing changes
timing and leaks a signal usable for client-ID enumeration. `invalid_client` covers both unknown
client and wrong credential, `error_description` never contains the `client_id`, and any opt-in
sub-code must not distinguish the two either. Presented secrets, raw `Authorization` headers, raw
token-endpoint bodies and `code_verifier` values are never logged (RFC 7636 §7.5).

**Registration-time validation has no runtime twin, and the analyzer is a backstop, not a
guarantee.** The iteration floor, the two-secret cap, the `IsPublic` consistency rule and the
allowlist subset checks are enforced only where a registration is written. The framework's own
in-memory repository validates at construction and throws before the host serves traffic; a custom
repository must resolve and call the same validator at write time. `ZEEKAYDA0003` warns when an
out-of-assembly repository never references the validator — it proves a reference, not a call.

**Client-facing types split on whether they need a request.** Registrations, credentials, hashers,
the repository and the validator are core; the authenticator seam and its request context types live
in the ASP.NET Core package.

## Tried, didn't work

- **Composite-side request-shape sniffing.** An earlier draft hard-coded "Basic header means
  `client_secret_basic`" in the composite. Caught in review: it defeats the extension point, because
  adding a method would have meant editing the composite.
- **A three-valued authentication outcome.** Needed only for chain-of-responsibility dispatch. Once
  the composite filters candidates first, at most one authenticator ever runs, and the outcome
  collapses to a binary flag.
