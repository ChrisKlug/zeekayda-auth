---
title: "Rotate signing keys"
description: "How signing key rotation and retirement work in ZeeKayDa.Auth, and how to rotate keys for each provider."
parent: "How-to Guides"
nav_order: 12
---

*Added in Unreleased.*

Every production signing key provider in ZeeKayDa.Auth shares the same rotation and
retirement model, even though the mechanics of *how* you introduce a new key differ per
provider. This guide explains that shared model once, then walks through the
provider-specific steps for each production provider.

For the underlying `IJwtSigningService` abstraction and how signing keys become a published
JWKS document, see [Signing keys](../reference/signing-keys.md).

## Before you start

- You already have a production signing key provider registered. If not, see
  [Configure signing keys: choosing a provider](configure-signing-keys.md) to pick one first.
- This guide does not apply to [development signing keys](configure-development-signing-keys.md) —
  those keys are never rotated; they are regenerated or replaced wholesale, and doing that in a
  non-development environment is already disallowed by the environment gate.

---

## Why rotate

You rotate a signing key for one of three reasons:

- **Compromise response.** If a private key may have been exposed, the only safe response is
  to stop signing with it and introduce a replacement.
- **Scheduled hygiene.** Rotating keys periodically limits how much can be signed with any one
  key over its lifetime, and is standard practice regardless of whether compromise is suspected.
- **Certificate expiry.** For the certificate-backed providers (Windows Certificate Store,
  file-based PEM/PFX), the certificate itself has a `NotAfter` date. You must rotate before it
  is reached, or the provider fails closed once no valid signing key remains.

---

## The model, in plain language

All production providers share the same three ideas. The [ADR 0011 §3.3 and §3.5](https://github.com/ChrisKlug/zeekayda-auth/blob/main/docs/decisions/0011-signing-key-management.md)
define this in full; this section is the developer-facing summary.

### A retired key's public half stays published for a while — its private half does not

When a new key takes over as the active signer, the old key does not disappear immediately.
Tokens signed with it are still out there — cached in browsers, held by APIs that haven't
re-validated yet — and those tokens still carry the old key's `kid` in their header. If the old
key's public half vanished from the JWKS the moment it stopped signing, every one of those
still-valid tokens would suddenly fail signature validation.

To avoid that, a retired key's **public** key stays published in the JWKS for a period called
the **retirement window**:

```
RetirementWindow = max(longest signature-validated token lifetime, 1-hour floor) + clock-skew allowance
```

In practice this means: the retirement window is at least as long as the longest-lived token a
relying party validates by checking its signature against the JWKS — today that's the ID token,
with a 1-hour floor applied until per-token lifetime configuration exists — plus a small margin
for clock skew between the authorization server and relying parties. You do not configure this
value directly; ZeeKayDa.Auth derives it from your token lifetime configuration.

The clock is measured **from the moment the key stops being the active signer**, not from when
the key was created. A key can sit in the trusted set unused as the active signer for a long
time before its successor takes over — the retirement window only starts counting once it is
actually retired.

> 💡 **Tip:** Refresh tokens are deliberately excluded from this calculation. A refresh token is
> never validated by a relying party checking a signature against the JWKS — it's redeemed by
> the authorization server against its own token store. Including a 14-day refresh token
> lifetime in the retirement window would keep every retired key published for two weeks for no
> validation benefit.

While the *public* half of a retired key lingers in the JWKS for the retirement window, its
**private** half is destroyed immediately on retirement. Once a key stops signing, it has no
further use, and keeping the private material around any longer than that is pure liability.

### Publish-then-activate: a new key must be seen before it signs anything

There's a symmetric risk on the way a key is introduced. Relying parties cache the JWKS — they
don't fetch it on every request. If a brand-new key started signing tokens before its public
half had ever appeared in a JWKS a relying party had fetched, that relying party would reject an
otherwise-valid token signed with a `kid` it has simply never seen.

ZeeKayDa.Auth's providers avoid this by requiring a new key to be **published** — visible in
`GetSigningKeysAsync()` results, and so in the JWKS — for some lead time **before** it is
promoted to active signer. That lead time is `SigningKeyActivationDelay` on the Azure Key Vault
options types, or `AssumedJwksPropagationDelay` on the Windows Certificate Store and file-based
PEM/PFX options types — both default to `KeyRotationCheckInterval` when left unset, which
defaults to **1 hour**. Set it to something at least as long as your relying parties' JWKS cache
TTL, and a relying party that polls the JWKS at that interval will always have observed a new key
before the first token is signed with it.

> ⚠️ **Warning:** The 1-hour default is a reasonable starting point, not a guarantee for every
> relying party. It comfortably clears ASP.NET Core's own JWKS-cache reactive refetch behavior,
> but a relying party with a longer fixed JWKS-cache TTL and no retry-on-miss logic is still
> exposed regardless of this default. Verify it against your actual relying parties' cache TTLs,
> and if you cannot, keep a published standby key on hand — see
> [Emergency key rotation](#emergency-key-rotation) below.

> ⚠️ **Warning:** For the certificate-backed providers (Windows Certificate Store, file-based
> PEM/PFX), `AssumedJwksPropagationDelay` is not itself enforced against a rotated-in
> certificate's `NotBefore` — see the provider-specific sections below for exactly what you have
> to do to satisfy it.

### The bootstrap exception

If a provider has exactly one key or certificate registered, that key is treated as the active
signer immediately, regardless of any activation timing. This is safe because there is no prior
published JWKS state any relying party could have cached — there's nothing for a new key to
race against. This exemption also covers the steady state right after a rotation finishes and the
old key has been removed from configuration: you're back down to one registered key, and it's
already been active and published for a while.

The bootstrap exemption never applies to expiry: a sole certificate whose `NotAfter` has already
passed is still rejected, and the provider fails closed with no active signing key rather than
sign with an expired certificate.

---

## Azure Key Vault — automatic

*See [Configure Azure Key Vault signing](configure-azure-key-vault-signing.md) for setup.*

Rotation for Azure Key Vault is automatic — there is no equivalent to the `AddCertificate(...)` /
`AddFile(...)` registration calls used by the other two providers. ZeeKayDa.Auth discovers new
key or certificate versions directly from the vault on every refresh; you do not register
versions in application configuration at all.

Your job as the operator is:

1. **Create the new key or certificate version in Key Vault** with enough lead time before it
   needs to be live — at least `SigningKeyActivationDelay`, so it has been visible to the provider
   (and therefore published in the JWKS) for at least that long before it becomes the active
   signer.
2. **Do not disable or delete the old version** until its retirement window has elapsed. The
   provider needs the old version's public key to remain available to keep validating tokens
   already signed with it.

If the active version's Key Vault `ExpiresOn` is reached with no enabled successor version, key
loading fails closed with a configuration error rather than silently continuing with an expired
key — rotate in the new version before the active one expires, not after.

---

## Windows Certificate Store and file-based (PEM/PFX) — manual registration

*See [Configure Windows Certificate Store signing](configure-windows-certificate-store-signing.md)
and [Configure file-based (PEM/PFX) signing](configure-file-based-signing.md) for setup.*

These two providers share the same rotation pattern, because both anchor their activation and
retirement timeline to the certificate's own `NotBefore`/`NotAfter` fields rather than to a
provider-recorded creation timestamp. Unlike Key Vault, their configuration is fixed at process
start — adding, removing, or replacing a certificate always requires a config change and a
restart.

> 💡 **Tip:** Why Key Vault gets an enforced overlap and these two don't. Key Vault stamps every
> key/certificate version with its own immutable `CreatedOn` timestamp the instant the version is
> created — a fact Key Vault itself remembers forever, independent of anything the operator
> supplies. ZeeKayDa.Auth uses that to compute each version's real activation time as
> `max(CreatedOn + SigningKeyActivationDelay, NotBefore)`, so a rotated-in Key Vault version can
> never activate sooner than one full `SigningKeyActivationDelay` after it was actually created —
> regardless of what `NotBefore` ends up being, including versions Key Vault's own automatic
> rotation policies create with no meaningfully-future `NotBefore` at all. A plain file or a
> Windows Certificate Store entry has no equivalent durable, tamper-proof "when was this actually
> created" timestamp for ZeeKayDa.Auth to anchor on — file modification time is explicitly not
> used for this because it resets on every redeploy of the identical file, which would make the
> library's activation timing depend on deployment mechanics rather than the certificate's actual
> age. That's why, for these two providers, `NotBefore` is the *only* signal, entirely under your
> control, with no library-enforced floor under it.

The rotation procedure is the same for both:

1. **Generate the new certificate or file**, setting its `NotBefore` at least
   `AssumedJwksPropagationDelay` in the future. This is the step that satisfies
   publish-then-activate for these two providers:
   because every registered certificate is already fully visible in the JWKS from process start,
   there is no separate "has this been published yet" delay the library can add on top — the
   `NotBefore` date *is* the activation time. You are responsible for setting it far enough
   ahead.

   > ⚠️ **Warning:** Most certificate tooling — `openssl`, PowerShell's
   > `New-SelfSignedCertificate` — defaults `NotBefore` to "now" unless you say otherwise. If you
   > don't override it deliberately, the new certificate activates immediately, and a relying
   > party that hasn't yet re-fetched the JWKS may reject a token signed with a `kid` it has never
   > seen.

2. **Register the new certificate or file alongside the existing one**, using `AddCertificate(...)`
   (Windows Certificate Store) or `AddFile(...)` (PEM/PFX), then deploy and restart. Both
   certificates are now registered; the old one is still active, the new one is pending
   activation until its `NotBefore` arrives.

3. **Wait out the old key's retirement window** after the new certificate has taken over as
   active signer, so relying parties holding tokens signed with the old key can still validate
   them.

4. **Remove the old certificate from configuration and restart again.** You're back down to one
   registered certificate, which is the bootstrap-exempt steady state described above.

### Example — file-based PEM signing

Before, with a single certificate registered:

```csharp
builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddPemFileSigning(
        path: "/etc/zeekayda/signing/current.pem",
        algorithm: SigningAlgorithm.RS256,
        configure: options =>
        {
            // 1 hour matches the built-in default shown here for clarity. Before copying this
            // value as-is, verify it exceeds your actual relying parties' JWKS-cache TTL — this
            // default is a reasonable starting point, not a guarantee for every relying party.
            options.KeyRotationCheckInterval = TimeSpan.FromHours(1);
        });
```

During rotation, with the new certificate registered alongside the old one — deploy this and
restart once the new file exists with its `NotBefore` set at least `AssumedJwksPropagationDelay`
(1 hour here, since it defaults to `KeyRotationCheckInterval`) in the future:

```csharp
builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddPemFileSigning(
        path: "/etc/zeekayda/signing/current.pem",
        algorithm: SigningAlgorithm.RS256,
        configure: options =>
        {
            options.KeyRotationCheckInterval = TimeSpan.FromHours(1);
            options.AddFile("/etc/zeekayda/signing/rotated-in.pem");
        });
```

After the new certificate has been active for at least the old certificate's retirement window,
remove the old file from configuration and restart again:

```csharp
builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddPemFileSigning(
        path: "/etc/zeekayda/signing/rotated-in.pem",
        algorithm: SigningAlgorithm.RS256,
        configure: options =>
        {
            options.KeyRotationCheckInterval = TimeSpan.FromHours(1);
        });
```

The Windows Certificate Store provider follows the identical pattern with `options.AddCertificate(thumbprint)`
in place of `options.AddFile(path)` — see
[Configure Windows Certificate Store signing](configure-windows-certificate-store-signing.md) for
the full registration call.

---

## Emergency key rotation

The procedures above assume you can plan ahead — you know a rotation is coming and can give a
new key the full publish-then-activate lead time before it needs to sign anything. A suspected
key compromise doesn't afford you that luxury, so the emergency path is different in two ways.

- **Keep a published standby key.** The fastest way to supersede an active key is to already
  have a second, unused key sitting in the trusted set (published in the JWKS, past its own
  activation delay, but not yet the active signer). Promoting a pre-published standby to active
  is immediate — there's no publish-then-activate wait, because it was published long ago. If you
  only ever register one key at a time, an emergency rotation has to generate a brand-new key and
  then wait out its full activation delay before it can safely take over, which is exactly the
  window an emergency response is trying to avoid. This is also the recommended mitigation for
  relying parties with a long, fixed JWKS-cache TTL and no retry-on-miss logic — see the warning
  above — since no `KeyRotationCheckInterval` value can fully compensate for that case.
- **Disabling a compromised key in the store takes effect immediately; detection of that change
  does not.** Disabling or deleting a Key Vault key/certificate version, or removing a
  certificate from the Windows Certificate Store, is instant from the store's point of view. But
  ZeeKayDa.Auth only notices on its next `KeyRotationCheckInterval` poll, and that poll is
  **traffic-gated** — it happens lazily, on the next call into the signing service, not on a
  background timer that fires on a schedule regardless of traffic. On a quiet deployment, the
  next poll could be well after one interval has nominally elapsed. The reliable emergency lever
  is not "disable it and wait": it's **disable it in the store, then restart or redeploy the
  process.** A restart forces an immediate cold `LoadKeysAsync`, which picks up the disabled key
  immediately regardless of the configured `KeyRotationCheckInterval` value.

---

## Troubleshooting

**Relying parties reject tokens that should still be valid.** You most likely removed the old
key from configuration (or disabled/deleted its Key Vault version) before its retirement window
had elapsed. Restore the old key if you still have it, and wait the full retirement window this
time before removing it.

**Relying parties reject tokens signed by the newly-active key, immediately after rotation.** You
most likely set the new certificate's `NotBefore` to "now" instead of at least
`AssumedJwksPropagationDelay` in the future — or, for Key Vault, created the new version and let
it activate without waiting `SigningKeyActivationDelay` for it to be observed. A relying party
with a cached JWKS from before the new key existed has no way to know about it yet. There is no
way to undo an early activation retroactively; the fix is to make sure the *next* rotation gives
the new key enough lead time.

---

## Related pages

- [Signing keys reference](../reference/signing-keys.md) — `IJwtSigningService`, `SigningKeySet`, and how keys are exposed as a JWKS document
- [Configure Azure Key Vault signing](configure-azure-key-vault-signing.md)
- [Configure Windows Certificate Store signing](configure-windows-certificate-store-signing.md)
- [Configure file-based (PEM/PFX) signing](configure-file-based-signing.md)

For the JWK wire format the JWKS publishes, see
[RFC 7517 (JSON Web Key)](https://www.rfc-editor.org/rfc/rfc7517).
