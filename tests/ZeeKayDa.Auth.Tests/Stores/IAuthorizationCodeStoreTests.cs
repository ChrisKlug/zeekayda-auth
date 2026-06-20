using System.Reflection;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Verifies the <em>contract shape</em> of <see cref="IAuthorizationCodeStore"/>: the interface
/// exists, exposes the two expected members with the correct signatures, and can be implemented
/// by a fake. No real implementation is exercised here.
/// </summary>
public sealed class IAuthorizationCodeStoreTests
{
    // ── Interface shape ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void IAuthorizationCodeStore_is_in_the_ZeeKayDa_Auth_Stores_namespace()
    {
        typeof(IAuthorizationCodeStore).Namespace.Should().Be("ZeeKayDa.Auth.Stores");
    }

    [Fact]
    public void IAuthorizationCodeStore_is_an_interface()
    {
        typeof(IAuthorizationCodeStore).IsInterface.Should().BeTrue();
    }

    [Fact]
    public void IAuthorizationCodeStore_declares_StoreAsync()
    {
        var method = typeof(IAuthorizationCodeStore).GetMethod(
            "StoreAsync",
            BindingFlags.Public | BindingFlags.Instance);

        method.Should().NotBeNull(because: "StoreAsync must be declared on the interface");
    }

    [Fact]
    public void StoreAsync_returns_Task()
    {
        var method = typeof(IAuthorizationCodeStore).GetMethod(
            "StoreAsync",
            BindingFlags.Public | BindingFlags.Instance)!;

        method.ReturnType.Should().Be(typeof(Task));
    }

    [Fact]
    public void StoreAsync_has_exactly_two_parameters()
    {
        var parameters = typeof(IAuthorizationCodeStore)
            .GetMethod("StoreAsync", BindingFlags.Public | BindingFlags.Instance)!
            .GetParameters();

        parameters.Should().HaveCount(2,
            because: "StoreAsync takes exactly (AuthorizationCodeEntry, CancellationToken)");
    }

    [Fact]
    public void StoreAsync_first_parameter_is_AuthorizationCodeEntry()
    {
        var parameters = typeof(IAuthorizationCodeStore)
            .GetMethod("StoreAsync", BindingFlags.Public | BindingFlags.Instance)!
            .GetParameters();

        parameters[0].ParameterType.Should().Be(typeof(AuthorizationCodeEntry));
    }

    [Fact]
    public void StoreAsync_second_parameter_is_CancellationToken()
    {
        var parameters = typeof(IAuthorizationCodeStore)
            .GetMethod("StoreAsync", BindingFlags.Public | BindingFlags.Instance)!
            .GetParameters();

        parameters[1].ParameterType.Should().Be(typeof(CancellationToken));
    }

    [Fact]
    public void IAuthorizationCodeStore_declares_TryRedeemAsync()
    {
        var method = typeof(IAuthorizationCodeStore).GetMethod(
            "TryRedeemAsync",
            BindingFlags.Public | BindingFlags.Instance);

        method.Should().NotBeNull(because: "TryRedeemAsync must be declared on the interface");
    }

    [Fact]
    public void TryRedeemAsync_returns_ValueTask_of_AuthorizationCodeRedemptionOutcome()
    {
        var method = typeof(IAuthorizationCodeStore).GetMethod(
            "TryRedeemAsync",
            BindingFlags.Public | BindingFlags.Instance)!;

        method.ReturnType.Should().Be(
            typeof(ValueTask<AuthorizationCodeRedemptionOutcome>));
    }

    [Fact]
    public void TryRedeemAsync_has_four_parameters()
    {
        var parameters = typeof(IAuthorizationCodeStore)
            .GetMethod("TryRedeemAsync", BindingFlags.Public | BindingFlags.Instance)!
            .GetParameters();

        parameters.Should().HaveCount(4);
    }

    [Fact]
    public void TryRedeemAsync_first_parameter_code_is_string()
    {
        var parameters = typeof(IAuthorizationCodeStore)
            .GetMethod("TryRedeemAsync", BindingFlags.Public | BindingFlags.Instance)!
            .GetParameters();

        parameters[0].ParameterType.Should().Be(typeof(string));
        parameters[0].Name.Should().Be("code");
    }

    [Fact]
    public void TryRedeemAsync_second_parameter_clientId_is_string()
    {
        var parameters = typeof(IAuthorizationCodeStore)
            .GetMethod("TryRedeemAsync", BindingFlags.Public | BindingFlags.Instance)!
            .GetParameters();

        parameters[1].ParameterType.Should().Be(typeof(string));
        parameters[1].Name.Should().Be("clientId");
    }

    [Fact]
    public void TryRedeemAsync_third_parameter_familyId_is_string()
    {
        var parameters = typeof(IAuthorizationCodeStore)
            .GetMethod("TryRedeemAsync", BindingFlags.Public | BindingFlags.Instance)!
            .GetParameters();

        parameters[2].ParameterType.Should().Be(typeof(string));
        parameters[2].Name.Should().Be("familyId");
    }

    [Fact]
    public void TryRedeemAsync_fourth_parameter_is_CancellationToken()
    {
        var parameters = typeof(IAuthorizationCodeStore)
            .GetMethod("TryRedeemAsync", BindingFlags.Public | BindingFlags.Instance)!
            .GetParameters();

        parameters[3].ParameterType.Should().Be(typeof(CancellationToken));
    }

    // ── Implementability via a fake ───────────────────────────────────────────────────────────────

    [Fact]
    public void A_fake_implementation_is_assignable_to_the_interface()
    {
        IAuthorizationCodeStore store = new FakeAuthorizationCodeStore(
            new AuthorizationCodeRedemptionOutcome.NotFound());

        store.Should().BeAssignableTo<IAuthorizationCodeStore>();
    }

    [Fact]
    public async Task Fake_StoreAsync_completes_without_throwing()
    {
        var store = new FakeAuthorizationCodeStore(
            new AuthorizationCodeRedemptionOutcome.NotFound());

        var act = async () => await store.StoreAsync(BuildEntry(), CancellationToken.None);

        await act.Should().NotThrowAsync();
    }

    [Fact]
    public async Task Fake_TryRedeemAsync_returns_configured_Redeemed_outcome()
    {
        var entry = BuildEntry();
        var store = new FakeAuthorizationCodeStore(
            new AuthorizationCodeRedemptionOutcome.Redeemed { Entry = entry });

        var outcome = await store.TryRedeemAsync(
            code:             "raw-code",
            clientId:         "client-a",
            familyId:         "family-1",
            cancellationToken: CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.Redeemed>()
            .Which.Entry.Should().BeSameAs(entry);
    }

    [Fact]
    public async Task Fake_TryRedeemAsync_returns_configured_ClientMismatch_outcome()
    {
        var store = new FakeAuthorizationCodeStore(
            new AuthorizationCodeRedemptionOutcome.ClientMismatch());

        var outcome = await store.TryRedeemAsync(
            code:             "raw-code",
            clientId:         "wrong-client",
            familyId:         "family-1",
            cancellationToken: CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.ClientMismatch>();
    }

    [Fact]
    public async Task Fake_TryRedeemAsync_returns_configured_AlreadyRedeemed_outcome()
    {
        var store = new FakeAuthorizationCodeStore(
            new AuthorizationCodeRedemptionOutcome.AlreadyRedeemed { FamilyId = "family-old" });

        var outcome = await store.TryRedeemAsync(
            code:             "replayed-code",
            clientId:         "client-a",
            familyId:         "family-new",
            cancellationToken: CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.AlreadyRedeemed>()
            .Which.FamilyId.Should().Be("family-old");
    }

    [Fact]
    public async Task Fake_TryRedeemAsync_returns_configured_NotFound_outcome()
    {
        var store = new FakeAuthorizationCodeStore(
            new AuthorizationCodeRedemptionOutcome.NotFound());

        var outcome = await store.TryRedeemAsync(
            code:             "unknown-code",
            clientId:         "client-a",
            familyId:         "family-1",
            cancellationToken: CancellationToken.None);

        outcome.Should().BeOfType<AuthorizationCodeRedemptionOutcome.NotFound>();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private static AuthorizationCodeEntry BuildEntry() =>
        new()
        {
            ClientId            = "client-a",
            RedirectUri         = "https://app/callback",
            CodeChallenge       = "challenge-abc",
            CodeChallengeMethod = CodeChallengeMethod.S256,
            Sub                 = "user-1",
            Scope               = "openid",
            SsoSessionId        = "session-1",
            InteractionId       = "interaction-1",
            AuthTime            = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero),
            IssuedAt            = new DateTimeOffset(2026, 1, 1, 12, 0, 0, TimeSpan.Zero),
            ExpiresAt           = new DateTimeOffset(2026, 1, 1, 12, 1, 0, TimeSpan.Zero),
        };

    /// <summary>
    /// Minimal fake store that returns a pre-configured outcome from TryRedeemAsync and does
    /// nothing in StoreAsync. Used only to prove the interface is implementable.
    /// </summary>
    private sealed class FakeAuthorizationCodeStore : IAuthorizationCodeStore
    {
        private readonly AuthorizationCodeRedemptionOutcome _outcome;

        public FakeAuthorizationCodeStore(AuthorizationCodeRedemptionOutcome outcome)
            => _outcome = outcome;

        public Task StoreAsync(AuthorizationCodeEntry entry, CancellationToken cancellationToken)
            => Task.CompletedTask;

        public ValueTask<AuthorizationCodeRedemptionOutcome> TryRedeemAsync(
            string code,
            string clientId,
            string familyId,
            CancellationToken cancellationToken)
            => ValueTask.FromResult(_outcome);
    }
}
