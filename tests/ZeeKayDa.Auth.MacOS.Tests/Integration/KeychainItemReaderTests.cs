// The genuinely macOS-only real-Keychain tests (AC #12). All gated with
// Assert.SkipUnless(OperatingSystem.IsMacOS(), ...) so they run only on the macos-latest CI leg and
// skip cleanly (not error) everywhere else. Every test installs its own uniquely-labelled item into
// the current user's login Keychain and removes it in a `finally`/`using` block, so tests can run
// repeatedly and in parallel without colliding.

using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.MacOS.Tests.Integration;

[SupportedOSPlatform("macos")]
public sealed class KeychainItemReaderTests
{
    private static readonly DateTimeOffset T0 = DateTimeOffset.UtcNow;

    // ── Bare keys ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void GetKey_finds_a_real_bare_RSA_key_and_signs_correctly()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), "requires a real macOS Keychain");

        using var installed = InstalledTestKeychainItems.CreateBareRsaKey();
        var reader = new KeychainItemReader();

        using var item = reader.GetKey(installed.Label);

        item.KeyType.Should().Be(SigningKeyType.Rsa);
        var rsa = (RSA)item.SigningKey;
        var payload = "zeekayda-macos-keychain-integration-test"u8.ToArray();
        var signature = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).Should().BeTrue();
    }

    [Fact]
    public void GetKey_finds_a_real_bare_EC_key_and_signs_correctly()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), "requires a real macOS Keychain");

        using var installed = InstalledTestKeychainItems.CreateBareEcKey();
        var reader = new KeychainItemReader();

        using var item = reader.GetKey(installed.Label);

        item.KeyType.Should().Be(SigningKeyType.Ec);
        var ecdsa = (ECDsa)item.SigningKey;
        var payload = "zeekayda-macos-keychain-integration-test-ec"u8.ToArray();
        var signature = ecdsa.SignData(payload, HashAlgorithmName.SHA256);
        ecdsa.VerifyData(payload, signature, HashAlgorithmName.SHA256).Should().BeTrue();
    }

    [Fact]
    public void GetKey_signing_key_never_exports_private_parameters()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), "requires a real macOS Keychain");

        using var installed = InstalledTestKeychainItems.CreateBareRsaKey();
        var reader = new KeychainItemReader();
        using var item = reader.GetKey(installed.Label);

        var act = () => ((RSA)item.SigningKey).ExportParameters(includePrivateParameters: true);

        act.Should().Throw<NotSupportedException>("raw private key bytes must never leave the Keychain/managed-heap boundary");
    }

    // ── Item exists but is not a usable private key (AC #9) ──────────────────────────────────────

    [Fact]
    public void GetKey_throws_not_a_private_key_when_the_label_only_matches_a_public_key()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), "requires a real macOS Keychain");

        using var installed = InstalledTestKeychainItems.CreatePublicKeyOnlyLabel();
        var reader = new KeychainItemReader();

        var act = () => reader.GetKey(installed.Label);

        act.Should().Throw<ZeeKayDaConfigurationException>().WithMessage("*not_a_private_key*");
    }

    [Fact]
    public void GetKey_throws_item_not_found_when_label_matches_nothing()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), "requires a real macOS Keychain");

        var reader = new KeychainItemReader();

        var act = () => reader.GetKey($"zeekayda-macos-test-missing-{Guid.NewGuid():N}");

        act.Should().Throw<ZeeKayDaConfigurationException>().WithMessage("*item_not_found*");
    }

    // ── Certificates / identities ─────────────────────────────────────────────────────────────────

    [Fact]
    public void TryGetCertificate_finds_a_real_identity_and_signs_correctly()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), "requires a real macOS Keychain");

        using var installed = InstalledTestKeychainItems.CreateIdentity(
            "zk-cert-test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var reader = new KeychainItemReader();

        var found = reader.TryGetCertificate(installed.Label, out var certificate);

        found.Should().BeTrue();
        using (certificate)
        {
            certificate!.Certificate.Subject.Should().Contain(installed.Label);
            certificate.KeyType.Should().Be(SigningKeyType.Rsa);

            var rsa = (RSA)certificate.SigningKey;
            var payload = "zeekayda-macos-identity-integration-test"u8.ToArray();
            var signature = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            certificate.Certificate.GetRSAPublicKey()!
                .VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                .Should().BeTrue("the signature must verify against the certificate's own public key");
        }
    }

    [Fact]
    public void TryGetCertificate_returns_false_when_label_matches_nothing()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), "requires a real macOS Keychain");

        var reader = new KeychainItemReader();

        var found = reader.TryGetCertificate($"zeekayda-macos-test-missing-{Guid.NewGuid():N}", out var certificate);

        found.Should().BeFalse();
        certificate.Should().BeNull();
    }

    [Fact]
    public void TryGetCertificate_throws_private_key_not_found_for_a_certificate_only_item()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), "requires a real macOS Keychain");

        using var installed = InstalledTestKeychainItems.CreateCertificateOnly(
            "zk-cert-only-test", T0 - TimeSpan.FromDays(1), T0 + TimeSpan.FromDays(365));
        var reader = new KeychainItemReader();

        var act = () => reader.TryGetCertificate(installed.Label, out _);

        act.Should().Throw<ZeeKayDaConfigurationException>().WithMessage("*private_key_not_found*");
    }

    // ── kid derivation (AC #3) ────────────────────────────────────────────────────────────────────

    [Fact]
    public void GetKey_kid_derived_via_JwkThumbprint_is_stable_and_not_the_Keychain_label()
    {
        Assert.SkipUnless(OperatingSystem.IsMacOS(), "requires a real macOS Keychain");

        using var installed = InstalledTestKeychainItems.CreateBareRsaKey();
        var reader = new KeychainItemReader();
        using var item = reader.GetKey(installed.Label);

        var descriptor = SigningKeyDescriptorFactory.BuildDescriptor(
            item.SigningKey, item.KeyType, SigningAlgorithm.RS256, "test.mismatch", _ => "unreachable");

        descriptor.Kid.Should().NotBeNullOrEmpty();
        descriptor.Kid.Should().NotContain(installed.Label);
    }
}
