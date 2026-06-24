using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class SigningKeySetTests
{
    private static (RSA Rsa, SigningKeyEntry Entry) MakeRsaEntry(string kid = "k1", int index = 0)
    {
        var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor(kid, SigningAlgorithm.RS256, rsaParams);
        return (rsa, new SigningKeyEntry(descriptor, index));
    }

    // ── Constructor validation ────────────────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_when_keys_is_null()
    {
        using var rsa = RSA.Create(2048);
        var act = () => new SigningKeySet(null!, [rsa]);
        act.Should().Throw<ArgumentNullException>().WithParameterName("keys");
    }

    [Fact]
    public void Constructor_throws_when_privateKeys_is_null()
    {
        var (_, entry) = MakeRsaEntry();
        var act = () => new SigningKeySet([entry], null!);
        act.Should().Throw<ArgumentNullException>().WithParameterName("privateKeys");
    }

    [Fact]
    public void Constructor_throws_when_keys_is_empty()
    {
        var act = () => new SigningKeySet([], []);
        act.Should().Throw<ArgumentException>().WithParameterName("keys");
    }

    [Fact]
    public void Constructor_throws_when_keys_and_privateKeys_lengths_differ()
    {
        var tuple = MakeRsaEntry();
        using var rsa = tuple.Rsa;
        var entry = tuple.Entry;
        using var rsa2 = RSA.Create(2048);
        var act = () => new SigningKeySet([entry], [rsa, rsa2]);
        act.Should().Throw<ArgumentException>().WithParameterName("privateKeys");
    }

    // ── Properties ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void ActiveKey_returns_first_entry()
    {
        var (rsa1, entry1) = MakeRsaEntry("k1", 0);
        var (rsa2, entry2) = MakeRsaEntry("k2", 1);
        using var set = new SigningKeySet([entry1, entry2], [rsa1, rsa2]);

        set.ActiveKey.Should().Be(entry1);
    }

    [Fact]
    public void GetPrivateKey_returns_correct_key_by_index()
    {
        var (rsa1, entry1) = MakeRsaEntry("k1", 0);
        var (rsa2, entry2) = MakeRsaEntry("k2", 1);
        using var set = new SigningKeySet([entry1, entry2], [rsa1, rsa2]);

        set.GetPrivateKey(0).Should().BeSameAs(rsa1);
        set.GetPrivateKey(1).Should().BeSameAs(rsa2);
    }

    // ── Disposal ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void GetPrivateKey_throws_ObjectDisposedException_after_Dispose()
    {
        var (rsa, entry) = MakeRsaEntry();
        using var set = new SigningKeySet([entry], [rsa]);

        set.Dispose();

        var act = () => set.GetPrivateKey(0);
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Dispose_can_be_called_multiple_times_without_throwing()
    {
        var (rsa, entry) = MakeRsaEntry();
        using var set = new SigningKeySet([entry], [rsa]);

        set.Dispose();
        var act = () => set.Dispose();

        act.Should().NotThrow();
    }
}
