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

    // ── Properties ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void ActiveKey_reflects_the_named_active_parameter_not_list_order()
    {
        var active = MakeRsaEntry("k1");
        var additional = MakeRsaEntry("k2");
        using var activeRsa = active.Rsa;
        using var additionalRsa = additional.Rsa;
        using var set = new SigningKeySet(active.Pair, [additional.Pair]);

        set.ActiveKey.Kid.Should().Be("k1");
    }

    [Fact]
    public void ActiveKey_reflects_the_named_active_parameter_even_when_additionalKeys_would_sort_earlier()
    {
        // additionalKeys is supplied in an order that, under the old positional convention,
        // would have made "k0" (not the named active key) look active. ActiveKey must still
        // report the named parameter.
        var active = MakeRsaEntry("k9");
        var additional = MakeRsaEntry("k0");
        using var activeRsa = active.Rsa;
        using var additionalRsa = additional.Rsa;
        using var set = new SigningKeySet(active.Pair, [additional.Pair]);

        set.ActiveKey.Kid.Should().Be("k9");
    }

    [Fact]
    public void Constructor_accepts_null_additionalKeys()
    {
        var active = MakeRsaEntry("k1");
        using var activeRsa = active.Rsa;
        using var set = new SigningKeySet(active.Pair, additionalKeys: null);

        set.ActiveKey.Kid.Should().Be("k1");
        set.Keys.Should().ContainSingle().Which.Kid.Should().Be("k1");
    }

    [Fact]
    public void Constructor_accepts_empty_additionalKeys()
    {
        var active = MakeRsaEntry("k1");
        using var activeRsa = active.Rsa;
        using var set = new SigningKeySet(active.Pair, []);

        set.ActiveKey.Kid.Should().Be("k1");
        set.Keys.Should().ContainSingle().Which.Kid.Should().Be("k1");
    }

    [Fact]
    public void Keys_is_active_first_then_additionalKeys_in_supplied_order()
    {
        var active = MakeRsaEntry("k1");
        var second = MakeRsaEntry("k2");
        var third = MakeRsaEntry("k3");
        using var activeRsa = active.Rsa;
        using var secondRsa = second.Rsa;
        using var thirdRsa = third.Rsa;
        using var set = new SigningKeySet(active.Pair, [second.Pair, third.Pair]);

        set.Keys.Select(k => k.Kid).Should().Equal("k1", "k2", "k3");
    }

    [Fact]
    public void GetPrivateKey_returns_correct_key_by_index()
    {
        var active = MakeRsaEntry("k1");
        var additional = MakeRsaEntry("k2");
        using var activeRsa = active.Rsa;
        using var additionalRsa = additional.Rsa;
        using var set = new SigningKeySet(active.Pair, [additional.Pair]);

        set.GetPrivateKey(0).Should().BeSameAs(activeRsa);
        set.GetPrivateKey(1).Should().BeSameAs(additionalRsa);
    }

    // ── Disposal ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void GetPrivateKey_throws_ObjectDisposedException_after_Dispose()
    {
        var tuple = MakeRsaEntry();
        using var rsa = tuple.Rsa;
        using var set = new SigningKeySet(tuple.Pair);

        set.Dispose();

        var act = () => set.GetPrivateKey(0);
        act.Should().Throw<ObjectDisposedException>();
    }

    [Fact]
    public void Dispose_can_be_called_multiple_times_without_throwing()
    {
        var tuple = MakeRsaEntry();
        using var rsa = tuple.Rsa;
        using var set = new SigningKeySet(tuple.Pair);

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
        using var set = new SigningKeySet(tuple.Pair);

        var borrowed = set.TryBorrow();

        borrowed.Should().BeTrue();

        // Balance the borrow so the set can be cleaned up by the using block.
        set.Return();
    }

    [Fact]
    public void TryBorrow_returns_false_after_Dispose()
    {
        var tuple = MakeRsaEntry();
        using var set = new SigningKeySet(tuple.Pair);

        set.Dispose(); // releases the cache's borrow; refcount drops to 0

        var borrowed = set.TryBorrow();

        borrowed.Should().BeFalse("a disposed set must not be borrowed");
    }

    [Fact]
    public void Private_keys_are_not_disposed_until_all_borrows_are_returned()
    {
        var tuple = MakeRsaEntry();
        var rsa = tuple.Rsa; // held to verify disposal state; the set also owns it
        using var set = new SigningKeySet(tuple.Pair);

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
