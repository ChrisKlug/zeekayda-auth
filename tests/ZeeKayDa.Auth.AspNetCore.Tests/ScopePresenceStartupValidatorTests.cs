using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

public sealed class ScopePresenceStartupValidatorTests
{
    private static (ScopePresenceStartupValidator Sut, ServiceProvider Provider) BuildSut(IScopeRepository repository)
    {
        var services = new ServiceCollection();
        services.AddSingleton(repository);
        services.AddSingleton<ValidatedScopeCatalog>();
        var provider = services.BuildServiceProvider();
        return (new ScopePresenceStartupValidator(), provider);
    }

    [Fact]
    public async Task VerifyAsync_completes_without_failures_when_openid_scope_is_present()
    {
        var (sut, provider) = BuildSut(new InMemoryScopeRepository([StandardScopes.OpenId]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_completes_when_openid_scope_is_among_several_scopes()
    {
        var (sut, provider) = BuildSut(new InMemoryScopeRepository(StandardScopes.All));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_when_openid_scope_is_missing()
    {
        var (sut, provider) = BuildSut(new InMemoryScopeRepository([StandardScopes.Profile]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle();
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_with_code_scopes_openid_missing()
    {
        var (sut, provider) = BuildSut(new InMemoryScopeRepository([]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle()
            .Which.Code.Should().Be("scopes.openid_missing");
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_with_message_containing_openid_scope_name()
    {
        var (sut, provider) = BuildSut(new InMemoryScopeRepository([]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Single().Message.Should().Contain(StandardScopes.OpenId.Name);
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_for_custom_repository_without_openid_scope()
    {
        var (sut, provider) = BuildSut(new CustomRepositoryWithoutOpenId());
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle();
    }

    // ── Audience: an RFC 8707 resource indicator ─────────────────────────────────────────────

    [Theory]
    [InlineData("https://orders.example.com/")]
    [InlineData("https://orders.example.com/api?v=2")]
    [InlineData("urn:example:orders")]
    public async Task VerifyAsync_accepts_an_absolute_URI_without_a_fragment_as_an_audience(string audience)
    {
        var (sut, provider) = BuildSut(new InMemoryScopeRepository(
            [StandardScopes.OpenId, new ScopeDefinition { Name = "orders.read", Audience = audience }]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    [Theory]
    [InlineData("orders")]
    [InlineData("/orders")]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("https://orders.example.com/#section")]
    [InlineData("https://orders.example.com/#")]
    public async Task VerifyAsync_adds_a_failure_when_an_audience_is_not_an_absolute_URI_without_a_fragment(string audience)
    {
        var (sut, provider) = BuildSut(new InMemoryScopeRepository(
            [StandardScopes.OpenId, new ScopeDefinition { Name = "orders.read", Audience = audience }]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle().Which.Code.Should().Be("scopes.audience.invalid");
    }

    [Fact]
    public async Task VerifyAsync_reports_every_invalid_audience_not_only_the_first()
    {
        var (sut, provider) = BuildSut(new InMemoryScopeRepository(
        [
            StandardScopes.OpenId,
            new ScopeDefinition { Name = "a", Audience = "not-a-uri" },
            new ScopeDefinition { Name = "b", Audience = "https://b.example.com/#x" },
        ]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().HaveCount(2);
    }

    // ── A custom repository's own output ──────────────────────────────────────────────────────

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task VerifyAsync_adds_a_failure_when_a_scope_has_no_name(string? name)
    {
        // InMemoryScopeRepository would refuse this in its constructor, but a custom repository
        // never runs that constructor and ScopeDefinition's non-nullable declarations are not
        // enforced at runtime. Unnamed, the scope is published into scopes_supported, which
        // Discovery 1.0 §3 defines as a list of strings.
        var (sut, provider) = BuildSut(new CustomRepository(
            [StandardScopes.OpenId, new ScopeDefinition { Name = name! }]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle().Which.Code.Should().Be("scopes.name.blank");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task VerifyAsync_adds_a_failure_when_a_scope_lists_a_claim_with_no_name(string? claim)
    {
        // ClaimRecord refuses a null, empty or whitespace claim type, so this claim can never be
        // delivered by any provider. Before this check the operator was told nothing: selection
        // carried the blank type and the discovery document quietly dropped it.
        var (sut, provider) = BuildSut(new CustomRepository(
            [StandardScopes.OpenId, new ScopeDefinition { Name = "custom", IdTokenClaims = [claim!] }]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle().Which.Code.Should().Be("scopes.claims.blank");
    }

    [Fact]
    public async Task VerifyAsync_reports_a_scope_listing_several_unnamed_claims_once()
    {
        // One failure names the scope and the fix; repeating it per blank entry would tell the
        // operator nothing new and pad a startup exception they have to read.
        var (sut, provider) = BuildSut(new CustomRepository(
        [
            StandardScopes.OpenId,
            new ScopeDefinition { Name = "custom", IdTokenClaims = ["", "  "], UserInfoClaims = [null!] },
        ]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle().Which.Code.Should().Be("scopes.claims.blank");
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_when_a_custom_repository_returns_null_claim_lists()
    {
        // Was tolerated by every consumer reading a null list as empty. The contract now says the
        // lists are never null, so the operator is told rather than left with a silent nothing.
        var (sut, provider) = BuildSut(new CustomRepository(
        [
            StandardScopes.OpenId,
            new ScopeDefinition { Name = "custom", IdTokenClaims = null!, UserInfoClaims = null!, AccessTokenClaims = null! },
        ]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().HaveCount(3).And.OnlyContain(f => f.Code == "scopes.claims.blank");
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_when_a_custom_repository_returns_null()
    {
        var (sut, provider) = BuildSut(new NullReturningRepository());
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().Contain(f => f.Code == "scopes.null");
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_when_a_custom_repository_returns_a_null_element()
    {
        var (sut, provider) = BuildSut(new CustomRepository([StandardScopes.OpenId, null!]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle().Which.Code.Should().Be("scopes.element.null");
    }

    [Fact]
    public async Task VerifyAsync_adds_a_failure_when_a_custom_repository_returns_duplicate_scope_names()
    {
        var (sut, provider) = BuildSut(new CustomRepository(
        [
            StandardScopes.OpenId,
            new ScopeDefinition { Name = "api", Audience = "https://api.example.com" },
            new ScopeDefinition { Name = "api", Audience = "https://other.example.com" },
        ]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle().Which.Code.Should().Be("scopes.name.duplicate");
    }

    [Fact]
    public async Task VerifyAsync_reports_every_broken_rule_at_once_not_only_the_first()
    {
        // One restart per failure is what an operator must not be made to pay.
        var (sut, provider) = BuildSut(new CustomRepository(
        [
            new ScopeDefinition { Name = "api", Audience = "not-a-uri" },
            new ScopeDefinition { Name = "api", AccessTokenClaims = ["nonce"] },
        ]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Select(f => f.Code).Should().BeEquivalentTo(
            ["scopes.name.duplicate", "scopes.claims.reserved", "scopes.audience.invalid", "scopes.openid_missing"]);
    }

    private sealed class NullReturningRepository : IScopeRepository
    {
        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult<IReadOnlyCollection<ScopeDefinition>>(null!);
    }

    // ── Reserved claim names in a scope's lists ───────────────────────────────────────────────

    [Theory]
    [InlineData("nonce")]
    [InlineData("Aud")]
    [InlineData("zkd:sid")]
    public async Task VerifyAsync_adds_a_failure_when_a_scope_lists_a_protocol_claim_it_could_never_deliver(string claim)
    {
        // The same name in a client addition fails registration; a scope listing it must not
        // pass silently and never deliver.
        var (sut, provider) = BuildSut(new InMemoryScopeRepository(
            [StandardScopes.OpenId, new ScopeDefinition { Name = "custom", AccessTokenClaims = [claim] }]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().ContainSingle().Which.Code.Should().Be("scopes.claims.reserved");
    }

    [Fact]
    public async Task VerifyAsync_accepts_sub_in_a_scope_list_as_the_standard_openid_scope_writes_it()
    {
        var (sut, provider) = BuildSut(new InMemoryScopeRepository(
            [StandardScopes.OpenId, new ScopeDefinition { Name = "custom", UserInfoClaims = ["sub", "tenant"] }]));
        using var _ = provider;
        var context = new StartupVerificationContext();

        await sut.VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        context.Failures.Should().BeEmpty();
    }

    private sealed class CustomRepositoryWithoutOpenId : IScopeRepository
    {
        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult<IReadOnlyCollection<ScopeDefinition>>([StandardScopes.Profile]);
    }

    /// <summary>
    /// A custom repository that returns whatever it is given. <c>InMemoryScopeRepository</c>
    /// validates in its constructor, so it cannot express the shapes these tests are about.
    /// </summary>
    private sealed class CustomRepository(IReadOnlyCollection<ScopeDefinition> scopes) : IScopeRepository
    {
        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(scopes);
    }
}
