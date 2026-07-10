---
title: "Rotate signing keys"
description: "How signing key rotation and retirement work in ZeeKayDa.Auth, and how to rotate keys for each provider."
parent: "How-to Guides"
nav_order: 11
---

*Added in Unreleased.*

Every production signing key provider in ZeeKayDa.Auth shares the same rotation and
retirement model, even though the mechanics of *how* you introduce a new key differ per
provider. This guide explains that shared model once, then walks through the
provider-specific steps for each production provider.

For the underlying `IJwtSigningService` abstraction and how signing keys become a published
JWKS document, see [Signing keys](../reference/signing-keys.md).

## Before you start

- You already have a production signing key provider registered. If not, pick one first:
  - [Configure Azure Key Vault signing](configure-azure-key-vault-signing.md)
  - [Configure Windows Certificate Store signing](configure-windows-certificate-store-signing.md)
  - [Configure file-based (PEM/PFX) signing](configure-file-based-signing.md)
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
promoted to active signer. That lead time is `RefreshInterval`, the same setting every provider's
options type inherits from `JwtSigningServiceOptions`. Set `RefreshInterval` to something at
least as long as your relying parties' JWKS cache TTL, and a relying party that polls the JWKS at
that interval will always have observed a new key before the first token is signed with it.

> ⚠️ **Warning:** `RefreshInterval` does double duty as this activation lead time for the
> certificate-backed providers (Windows Certificate Store, file-based PEM/PFX) — see the
> provider-specific sections below for exactly what you have to do to satisfy it.

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
   needs to be live — at least `RefreshInterval`, so it has been visible to the provider (and
   therefore published in the JWKS) for at least that long before it becomes the active signer.
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

The rotation procedure is the same for both:

1. **Generate the new certificate or file**, setting its `NotBefore` at least `RefreshInterval`
   in the future. This is the step that satisfies publish-then-activate for these two providers:
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
        configure: options =>
        {
            options.RefreshInterval = TimeSpan.FromMinutes(10);
        });
```

During rotation, with the new certificate registered alongside the old one — deploy this and
restart once the new file exists with its `NotBefore` set at least `RefreshInterval` (10 minutes,
here) in the future:

```csharp
builder.Services
    .AddZeeKayDaAuth(options =>
    {
        options.Issuer = "https://id.example.com";
    })
    .AddPemFileSigning(
        path: "/etc/zeekayda/signing/current.pem",
        configure: options =>
        {
            options.RefreshInterval = TimeSpan.FromMinutes(10);
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
        configure: options =>
        {
            options.RefreshInterval = TimeSpan.FromMinutes(10);
        });
```

The Windows Certificate Store provider follows the identical pattern with `options.AddCertificate(thumbprint)`
in place of `options.AddFile(path)` — see
[Configure Windows Certificate Store signing](configure-windows-certificate-store-signing.md) for
the full registration call.

---

## Troubleshooting

**Relying parties reject tokens that should still be valid.** You most likely removed the old
key from configuration (or disabled/deleted its Key Vault version) before its retirement window
had elapsed. Restore the old key if you still have it, and wait the full retirement window this
time before removing it.

**Relying parties reject tokens signed by the newly-active key, immediately after rotation.** You
most likely set the new certificate's `NotBefore` to "now" instead of at least `RefreshInterval`
in the future — or, for Key Vault, created the new version and let it activate without waiting
`RefreshInterval` for it to be observed. A relying party with a cached JWKS from before the new
key existed has no way to know about it yet. There is no way to undo an early activation
retroactively; the fix is to make sure the *next* rotation gives the new key enough lead time.

---

## Related pages

- [Signing keys reference](../reference/signing-keys.md) — `IJwtSigningService`, `SigningKeySet`, and how keys are exposed as a JWKS document
- [Configure Azure Key Vault signing](configure-azure-key-vault-signing.md)
- [Configure Windows Certificate Store signing](configure-windows-certificate-store-signing.md)
- [Configure file-based (PEM/PFX) signing](configure-file-based-signing.md)

For the JWK wire format the JWKS publishes, see
[RFC 7517 (JSON Web Key)](https://www.rfc-editor.org/rfc/rfc7517).
