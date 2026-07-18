using System.Reflection;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Verifies the sealing mechanism of <see cref="IRefreshTokenStore"/> (ADR 0014 §4, mirroring ADR
/// 0013 §1): the interface stays implementable from a friend assembly (this test project), but
/// carries exactly one internal member that blocks a genuine third-party implementation.
/// </summary>
public sealed class IRefreshTokenStoreTests
{
    [Fact]
    public void IRefreshTokenStore_is_in_the_ZeeKayDa_Auth_Stores_namespace()
    {
        typeof(IRefreshTokenStore).Namespace.Should().Be("ZeeKayDa.Auth.Stores");
    }

    [Fact]
    public void IRefreshTokenStore_declares_exactly_one_internal_method()
    {
        var internalMethods = typeof(IRefreshTokenStore)
            .GetMethods(BindingFlags.NonPublic | BindingFlags.Instance)
            .Where(m => !m.IsPublic)
            .ToList();

        internalMethods.Should().ContainSingle(
            because: "an internal member is what blocks third-party implementation of this " +
                     "framework-sealed interface (ADR 0014 §4, ADR 0013 §1), and there must be exactly one");
    }

    [Fact]
    public void IRefreshTokenStore_internal_method_is_named_SealAsFrameworkOwnedProtocol()
    {
        var internalMethod = typeof(IRefreshTokenStore)
            .GetMethods(BindingFlags.NonPublic | BindingFlags.Instance)
            .Single(m => !m.IsPublic);

        internalMethod.Name.Should().Be("SealAsFrameworkOwnedProtocol");
    }

    // ── Implementability via a fake (this project is a named friend assembly) ───────────────────

    [Fact]
    public void A_fake_implementation_is_assignable_to_the_interface()
    {
        IRefreshTokenStore store = new FakeRefreshTokenStore(new RefreshTokenConsumptionResult.NotFound());

        store.Should().BeAssignableTo<IRefreshTokenStore>();
    }

    [Fact]
    public async Task Fake_StoreAsync_completes_without_throwing()
    {
        var store = new FakeRefreshTokenStore(new RefreshTokenConsumptionResult.NotFound());

        var act = async () => await store.StoreAsync("raw-handle", BuildEntry(), CancellationToken.None);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task Fake_TryConsumeAsync_returns_configured_Consumed_outcome()
    {
        var entry = BuildEntry();
        var store = new FakeRefreshTokenStore(new RefreshTokenConsumptionResult.Consumed { Entry = entry });

        var outcome = await store.TryConsumeAsync("raw-handle", "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.Consumed>()
            .Which.Entry.Should().BeSameAs(entry);
    }

    [Fact]
    public async Task Fake_TryConsumeAsync_returns_configured_ClientMismatch_outcome()
    {
        var store = new FakeRefreshTokenStore(new RefreshTokenConsumptionResult.ClientMismatch());

        var outcome = await store.TryConsumeAsync("raw-handle", "wrong-client", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.ClientMismatch>();
    }

    [Fact]
    public async Task Fake_TryConsumeAsync_returns_configured_AlreadyConsumed_outcome()
    {
        var store = new FakeRefreshTokenStore(new RefreshTokenConsumptionResult.AlreadyConsumed { FamilyId = "fam-old" });

        var outcome = await store.TryConsumeAsync("replayed-handle", "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.AlreadyConsumed>()
            .Which.FamilyId.Should().Be("fam-old");
    }

    [Fact]
    public async Task Fake_TryConsumeAsync_returns_configured_Revoked_outcome()
    {
        var store = new FakeRefreshTokenStore(new RefreshTokenConsumptionResult.Revoked { FamilyId = "fam-revoked" });

        var outcome = await store.TryConsumeAsync("revoked-handle", "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.Revoked>()
            .Which.FamilyId.Should().Be("fam-revoked");
    }

    [Fact]
    public async Task Fake_TryConsumeAsync_returns_configured_NotFound_outcome()
    {
        var store = new FakeRefreshTokenStore(new RefreshTokenConsumptionResult.NotFound());

        var outcome = await store.TryConsumeAsync("unknown-handle", "client-a", CancellationToken.None);

        outcome.Should().BeOfType<RefreshTokenConsumptionResult.NotFound>();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private static RefreshTokenEntry BuildEntry() =>
        new()
        {
            FamilyId = "fam-1",
            ClientId = "client-a",
            Sub = "user-1",
            Scope = ["openid"],
            SsoSessionId = "session-1",
            IssuedAt = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero),
            ExpiresAt = new DateTimeOffset(2026, 1, 1, 12, 1, 0, TimeSpan.Zero),
            FamilyAbsoluteExpiry = new DateTimeOffset(2026, 4, 1, 12, 0, 0, TimeSpan.Zero),
        };

    /// <summary>
    /// Minimal fake store that returns a pre-configured outcome from TryConsumeAsync and does
    /// nothing else. Used only to prove the interface is implementable from a friend assembly.
    /// </summary>
    private sealed class FakeRefreshTokenStore : IRefreshTokenStore
    {
        private readonly RefreshTokenConsumptionResult _outcome;

        public FakeRefreshTokenStore(RefreshTokenConsumptionResult outcome) => _outcome = outcome;

        public Task StoreAsync(string tokenHandle, RefreshTokenEntry entry, CancellationToken cancellationToken)
            => Task.CompletedTask;

        public ValueTask<RefreshTokenEntry?> FindAsync(string tokenHandle, CancellationToken cancellationToken)
            => ValueTask.FromResult<RefreshTokenEntry?>(null);

        public ValueTask<RefreshTokenConsumptionResult> TryConsumeAsync(
            string tokenHandle,
            string clientId,
            CancellationToken cancellationToken)
            => ValueTask.FromResult(_outcome);

        public Task RevokeFamilyAsync(string familyId, CancellationToken cancellationToken)
            => Task.CompletedTask;

        // Satisfiable here because ZeeKayDa.Auth.Tests is a friend assembly (ADR 0014 §4, ADR 0013
        // §1) — a genuine third-party assembly could not implement IRefreshTokenStore at all.
        void IRefreshTokenStore.SealAsFrameworkOwnedProtocol() { }
    }
}
