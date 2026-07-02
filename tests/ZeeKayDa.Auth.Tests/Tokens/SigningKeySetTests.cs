using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

public sealed class SigningKeySetTests
{
    private static (RSA Rsa, SigningKeyPair Pair) MakeRsaEntry(string kid = "k1")
    {
        var rsa = RSA.Create(2048);
        var rsaParams = rsa.ExportParameters(false);
        var descriptor = new SigningKeyDescriptor(kid, SigningAlgorithm.RS256, rsaParams);
        return (rsa, new SigningKeyPair { Descriptor = descriptor, PrivateKey = rsa });
    }

    // ── Constructor validation ────────────────────────────────────────────────────────────────────

    [Fact]
    public void Constructor_throws_when_keys_is_null()
    {
        var act = () => new SigningKeySet(null!);
        act.Should().Throw<ArgumentNullException>().WithParameterName("keys");
    }

    [Fact]
    public void Constructor_throws_when_keys_is_empty()
    {
        var act = () => new SigningKeySet([]);
        act.Should().Throw<ArgumentException>().WithParameterName("keys");
    }

    // ── Properties ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void ActiveKey_returns_first_entry()
    {
        var tuple1 = MakeRsaEntry("k1");
        var tuple2 = MakeRsaEntry("k2");
        using var rsa1 = tuple1.Rsa;
        using var rsa2 = tuple2.Rsa;
        using var set = new SigningKeySet([tuple1.Pair, tuple2.Pair]);

        set.ActiveKey.Descriptor.Kid.Should().Be("k1");
    }

    [Fact]
    public void GetPrivateKey_returns_correct_key_by_index()
    {
        var tuple1 = MakeRsaEntry("k1");
        var tuple2 = MakeRsaEntry("k2");
        using var rsa1 = tuple1.Rsa;
        using var rsa2 = tuple2.Rsa;
        using var set = new SigningKeySet([tuple1.Pair, tuple2.Pair]);

        set.GetPrivateKey(0).Should().BeSameAs(rsa1);
        set.GetPrivateKey(1).Should().BeSameAs(rsa2);
    }

    // ── Disposal ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void GetPrivateKey_throws_ObjectDisposedException_after_Dispose()
    {
        var tuple = MakeRsaEntry();
        using var rsa = tuple.Rsa;
        using var set = new SigningKeySet([tuple.Pair]);

        set.Dispose();

        var act = () => set.GetPrivateKey(0);
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Dispose_can_be_called_multiple_times_without_throwing()
    {
        var tuple = MakeRsaEntry();
        using var rsa = tuple.Rsa;
        using var set = new SigningKeySet([tuple.Pair]);

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
        using var set = new SigningKeySet([tuple.Pair]);

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
        var set = new SigningKeySet([tuple.Pair]);
        try
        {
            set.Dispose(); // releases the cache's borrow; refcount drops to 0

            var borrowed = set.TryBorrow();

            borrowed.Should().BeFalse("a disposed set must not be borrowed");
        }
        finally
        {
            // Dispose again is safe (idempotent) and ensures cleanup if an assertion throws
            // before the explicit Dispose above runs.
            set.Dispose();
        }
    }

    [Fact]
    public void Private_keys_are_not_disposed_until_all_borrows_are_returned()
    {
        var tuple = MakeRsaEntry();
        // Do not use `using var rsa` — we verify disposal state manually.
        var rsa = tuple.Rsa;
        var set = new SigningKeySet([tuple.Pair]);
        try
        {
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
        finally
        {
            // Ensure the set is always disposed even if an assertion throws before the
            // explicit Dispose() and Return() above. Dispose() is idempotent.
            set.Dispose();
        }
    }
}
