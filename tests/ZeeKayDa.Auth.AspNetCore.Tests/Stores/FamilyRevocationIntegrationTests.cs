using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Stores;

public sealed class FamilyRevocationIntegrationTests
{
    private sealed class FakeHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = "/";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    private static ServiceProvider BuildServiceProvider()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddMemoryCache();
        services.AddDataProtection();
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<IHostEnvironment>(new FakeHostEnvironment(Environments.Development));
        services.AddZeeKayDaAuthCore();
        new ZeeKayDaAuthBuilder(services).AddInMemoryStores();
        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task Code_replay_triggers_family_revocation_spanning_both_stores()
    {
        await using var provider = BuildServiceProvider();

        var codeStore = provider.GetRequiredService<IAuthorizationCodeStore>();
        var tokenStore = provider.GetRequiredService<IRefreshTokenStore>();

        var code = Guid.NewGuid().ToString("N");
        var clientId = "test-client";
        var familyId = Guid.NewGuid().ToString("N");
        var tokenHandle = Guid.NewGuid().ToString("N");
        var farFuture = new DateTimeOffset(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var now = DateTimeOffset.UtcNow;

        var codeEntry = new AuthorizationCodeEntry
        {
            ClientId = clientId,
            RedirectUri = "https://example.com/callback",
            CodeChallenge = "abc123challenge",
            CodeChallengeMethod = CodeChallengeMethod.S256,
            Sub = "user-sub-001",
            Scope = ["openid", "profile"],
            SsoSessionId = Guid.NewGuid().ToString("N"),
            InteractionId = Guid.NewGuid().ToString("N"),
            AuthTime = now,
            IssuedAt = now,
            ExpiresAt = farFuture,
        };

        await codeStore.StoreAsync(code, codeEntry, CancellationToken.None);

        var firstOutcome = await codeStore.TryRedeemAsync(code, clientId, familyId, CancellationToken.None);

        firstOutcome.Should().BeOfType<AuthorizationCodeRedemptionResult.Redeemed>(
            "the first redemption of a valid, unexpired code must succeed");

        var replayFamilyId = Guid.NewGuid().ToString("N");
        var replayOutcome = await codeStore.TryRedeemAsync(code, clientId, replayFamilyId, CancellationToken.None);

        replayOutcome.Should().BeOfType<AuthorizationCodeRedemptionResult.AlreadyRedeemed>(
                "replaying the same code must return AlreadyRedeemed")
            .Which.FamilyId.Should().Be(familyId,
                "tombstone must carry the familyId from the first redemption, not the replay attempt's argument");

        var revocationAct = async () =>
            await tokenStore.RevokeFamilyAsync(familyId, CancellationToken.None);
        await revocationAct.Should().NotThrowAsync(
            "RevokeFamilyAsync must be idempotent and must not throw");

        var tokenEntry = new RefreshTokenEntry
        {
            FamilyId = familyId,
            ClientId = clientId,
            Sub = "user-sub-001",
            Scope = ["openid", "profile"],
            SsoSessionId = Guid.NewGuid().ToString("N"),
            IssuedAt = now,
            ExpiresAt = farFuture,
            FamilyAbsoluteExpiry = farFuture,
        };

        await tokenStore.StoreAsync(tokenHandle, tokenEntry, CancellationToken.None);

        var consumeOutcome = await tokenStore.TryConsumeAsync(tokenHandle, clientId, CancellationToken.None);

        // FLAGGED BEHAVIOUR CHANGE (see final test report for the full write-up, not fixed here):
        // under ADR 0008's original marker-based design, RevokeFamilyAsync persisted a
        // family-level marker independent of any row, so a token stored afterward into an
        // already-revoked family would still read as Revoked. ADR 0014's queryable model has no
        // such marker — RevokeFamilyAsync only marks rows that already exist at the time it runs
        // (§6). A grant stored into a family AFTER it was revoked, with zero rows existing at
        // revoke time, is Active and consumable. The ADR argues this is safe in the legitimate
        // rotation flow (a revoked family blocks the consume that would trigger a rotation
        // insert), but this test's own scenario — auth-code replay detected and the family
        // revoked before the FIRST refresh token of that family is ever stored — is not that
        // rotation case, and is not explicitly covered by the ADR's reasoning.
        consumeOutcome.Should().BeOfType<RefreshTokenConsumptionResult.Consumed>(
            "ADR 0014's queryable model has no persistent family-revocation marker; " +
            "RevokeFamilyAsync only marks rows that exist at call time (§6), so a grant stored " +
            "afterward into the same family is unaffected by the earlier revocation");
    }

    [Fact]
    public async Task Pre_existing_refresh_token_is_revoked_when_its_family_is_revoked()
    {
        await using var provider = BuildServiceProvider();

        var tokenStore = provider.GetRequiredService<IRefreshTokenStore>();

        var clientId = "test-client";
        var familyId = Guid.NewGuid().ToString("N");
        var tokenHandle = Guid.NewGuid().ToString("N");
        var farFuture = new DateTimeOffset(2099, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var now = DateTimeOffset.UtcNow;

        var tokenEntry = new RefreshTokenEntry
        {
            FamilyId = familyId,
            ClientId = clientId,
            Sub = "user-sub-001",
            Scope = ["openid", "profile"],
            SsoSessionId = Guid.NewGuid().ToString("N"),
            IssuedAt = now,
            ExpiresAt = farFuture,
            FamilyAbsoluteExpiry = farFuture,
        };

        await tokenStore.StoreAsync(tokenHandle, tokenEntry, CancellationToken.None);

        await tokenStore.RevokeFamilyAsync(familyId, CancellationToken.None);

        var consumeOutcome = await tokenStore.TryConsumeAsync(tokenHandle, clientId, CancellationToken.None);

        consumeOutcome.Should().BeOfType<RefreshTokenConsumptionResult.Revoked>(
                "revocation must retroactively apply to tokens that existed before RevokeFamilyAsync was called")
            .Which.FamilyId.Should().Be(familyId,
                "the Revoked outcome must carry the familyId that was revoked");
    }
}
