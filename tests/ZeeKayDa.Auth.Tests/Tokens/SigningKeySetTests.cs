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
        var tuple = MakeRsaEntry();
        using var rsa = tuple.Rsa;
        var entry = tuple.Entry;
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
        var tuple1 = MakeRsaEntry("k1", 0);
        var tuple2 = MakeRsaEntry("k2", 1);
        using var rsa1 = tuple1.Rsa;
        using var rsa2 = tuple2.Rsa;
        using var set = new SigningKeySet([tuple1.Entry, tuple2.Entry], [rsa1, rsa2]);

        set.ActiveKey.Should().Be(tuple1.Entry);
    }

    [Fact]
    public void GetPrivateKey_returns_correct_key_by_index()
    {
        var tuple1 = MakeRsaEntry("k1", 0);
        var tuple2 = MakeRsaEntry("k2", 1);
        using var rsa1 = tuple1.Rsa;
        using var rsa2 = tuple2.Rsa;
        using var set = new SigningKeySet([tuple1.Entry, tuple2.Entry], [rsa1, rsa2]);

        set.GetPrivateKey(0).Should().BeSameAs(rsa1);
        set.GetPrivateKey(1).Should().BeSameAs(rsa2);
    }

    // ── Disposal ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void GetPrivateKey_throws_ObjectDisposedException_after_Dispose()
    {
        var tuple = MakeRsaEntry();
        using var rsa = tuple.Rsa;
        using var set = new SigningKeySet([tuple.Entry], [rsa]);

        set.Dispose();

        var act = () => set.GetPrivateKey(0);
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Dispose_can_be_called_multiple_times_without_throwing()
    {
        var tuple = MakeRsaEntry();
        using var rsa = tuple.Rsa;
        using var set = new SigningKeySet([tuple.Entry], [rsa]);

        set.Dispose();
        var act = () => set.Dispose();

        act.Should().NotThrow();
    }

    // ── Reference counting ────────────────────────────────────────────────────────────────────────

    [Fact]
    public void TryBorrow_returns_true_on_a_live_set()
    {
        var tuple = MakeRsaEntry();
        using var rsa = tuple.Rsa;
        using var set = new SigningKeySet([tuple.Entry], [rsa]);

        var borrowed = set.TryBorrow();

        borrowed.Should().BeTrue();

        // Balance the borrow so the set can be cleaned up by the using block.
        set.Return();
    }

    [Fact]
    public void TryBorrow_returns_false_after_Dispose()
    {
        var tuple = MakeRsaEntry();
        // Do not use `using var rsa` — the set takes ownership and disposes it.
        var rsa = tuple.Rsa;
        var set = new SigningKeySet([tuple.Entry], [rsa]);

        set.Dispose(); // releases the cache's borrow; refcount drops to 0

        var borrowed = set.TryBorrow();

        borrowed.Should().BeFalse("a disposed set must not be borrowed");
    }

    [Fact]
    public void Private_keys_are_not_disposed_until_all_borrows_are_returned()
    {
        var tuple = MakeRsaEntry();
        // Do not use `using var rsa` — we verify disposal state manually.
        var rsa = tuple.Rsa;
        var set = new SigningKeySet([tuple.Entry], [rsa]);

        // Acquire a borrow (simulates a fast-path caller about to sign).
        var borrowed = set.TryBorrow();
        borrowed.Should().BeTrue();

        // Dispose the set (simulates DisposeAsync or a cache refresh).
        set.Dispose();

        // The RSA is not yet disposed because the borrow is still outstanding.
        var canExport = () => rsa.ExportParameters(false);
        canExport.Should().NotThrow("key must remain usable while a borrow is outstanding");

        // Return the borrow — now refcount hits zero and keys are disposed.
        set.Return();

        var cannotExport = () => rsa.ExportParameters(false);
        cannotExport.Should().Throw<ObjectDisposedException>(
            "key must be disposed once all borrows are returned");
    }
}
