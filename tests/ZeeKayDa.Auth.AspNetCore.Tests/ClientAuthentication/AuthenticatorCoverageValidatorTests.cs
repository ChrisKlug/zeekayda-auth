using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.ClientAuthentication;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.ClientAuthentication;

public sealed class AuthenticatorCoverageValidatorTests
{
    // ── Fake authenticator ────────────────────────────────────────────────────────────────────────

    private sealed class FakeAuthenticator : IClientAuthenticator
    {
        public FakeAuthenticator(params string[] methods) =>
            AuthenticationMethods = new HashSet<string>(methods, StringComparer.Ordinal);

        public IReadOnlySet<string> AuthenticationMethods { get; }

        public bool CanHandle(TokenRequestContext context, out string? method)
        {
            method = null;
            return false;
        }

        public ValueTask<ClientAuthenticationResult> AuthenticateAsync(
            ClientAuthenticationContext context, CancellationToken ct) =>
            ValueTask.FromResult(ClientAuthenticationResult.NotValid());
    }

    /// <summary>
    /// A sentinel interface that is never registered in any DI container. Used as the unsatisfied
    /// constructor dependency on <see cref="BrokenAuthenticator"/> to force a DI resolution failure.
    /// </summary>
    private interface IUnregisteredDependency { }

    /// <summary>
    /// An authenticator whose constructor has an unsatisfied DI dependency. Registering this
    /// by type (not instance) causes <c>GetServices&lt;IClientAuthenticator&gt;()</c> to throw
    /// during construction.
    /// </summary>
    private sealed class BrokenAuthenticator : IClientAuthenticator
    {
        // The dependency is intentionally never registered — DI throws before the body runs.
#pragma warning disable IDE0060 // Remove unused parameter
        public BrokenAuthenticator(IUnregisteredDependency _) { }
#pragma warning restore IDE0060

        public IReadOnlySet<string> AuthenticationMethods =>
            new HashSet<string>(StringComparer.Ordinal);

        public bool CanHandle(TokenRequestContext context, out string? method)
        {
            method = null;
            return false;
        }

        public ValueTask<ClientAuthenticationResult> AuthenticateAsync(
            ClientAuthenticationContext context, CancellationToken ct) =>
            ValueTask.FromResult(ClientAuthenticationResult.NotValid());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private static async Task<IReadOnlyList<ZeeKayDaConfigurationFailure>> VerifyAsync(
        string[] serverMethods,
        params IClientAuthenticator[] authenticators)
    {
        var services = new ServiceCollection();
        foreach (var a in authenticators)
            services.AddSingleton(a);

        return await VerifyAsync(services, serverMethods);
    }

    private static async Task<IReadOnlyList<ZeeKayDaConfigurationFailure>> VerifyAsync(
        ServiceCollection services,
        string[] serverMethods)
    {
        var options = new AuthorizationServerOptions();
        options.TokenEndpoint.AuthMethodsSupported = [.. serverMethods];

        await using var provider = services.BuildServiceProvider();
        var context = new StartupVerificationContext();

        await new AuthenticatorCoverageValidator(Options.Create(options))
            .VerifyAsync(context, provider, TestContext.Current.CancellationToken);

        return context.Failures;
    }

    // ── Happy path ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Verify_succeeds_when_all_server_methods_are_covered_by_registered_authenticators()
    {
        var failures = await VerifyAsync(
            [TokenEndpointAuthMethods.ClientSecretBasic],
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic));

        failures.Should().BeEmpty();
    }

    [Fact]
    public async Task Verify_succeeds_when_none_is_in_server_methods_without_a_matching_authenticator()
    {
        // "none" is always covered by the composite fallback — no authenticator needed.
        var failures = await VerifyAsync(
            [TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.None],
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic));

        failures.Should().BeEmpty();
    }

    [Fact]
    public async Task Verify_succeeds_when_multiple_authenticators_each_cover_distinct_methods()
    {
        var failures = await VerifyAsync(
            [TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.ClientSecretPost],
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic),
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretPost));

        failures.Should().BeEmpty();
    }

    // ── Whitespace in method string ───────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("client_secret_basic ")]   // trailing space
    [InlineData(" client_secret_basic")]   // leading space
    [InlineData(" client_secret_basic ")]  // both
    [InlineData("client_secret_post ")]    // trailing space on a different known method
    [InlineData(" none")]                  // leading space on the reserved method
    public async Task Verify_fails_when_authenticator_declares_method_with_surrounding_whitespace(
        string methodWithWhitespace)
    {
        var failures = await VerifyAsync(
            [TokenEndpointAuthMethods.ClientSecretBasic],
            new FakeAuthenticator(methodWithWhitespace));

        failures.Should().Contain(failure =>
            failure.Code == "authenticators.method_whitespace" &&
            failure.Message.Contains("whitespace"));
    }

    // ── Non-canonical casing ──────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("Client_Secret_Basic")]    // title-case
    [InlineData("CLIENT_SECRET_BASIC")]    // upper-case
    [InlineData("CLIENT_SECRET_POST")]     // upper-case on a different known method
    [InlineData("Client_Secret_Post")]     // title-case on a different known method
    [InlineData("NONE")]                   // upper-case on the reserved method
    public async Task Verify_fails_when_authenticator_declares_known_method_with_wrong_casing(
        string methodWithWrongCasing)
    {
        var failures = await VerifyAsync(
            [TokenEndpointAuthMethods.ClientSecretBasic],
            new FakeAuthenticator(methodWithWrongCasing));

        failures.Should().Contain(failure =>
            failure.Code == "authenticators.method_casing" &&
            failure.Message.Contains("canonical"));
    }

    // ── none reserved ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Verify_fails_when_an_authenticator_declares_none()
    {
        var failures = await VerifyAsync(
            [TokenEndpointAuthMethods.None],
            new FakeAuthenticator(TokenEndpointAuthMethods.None));

        failures.Should().ContainSingle()
            .Which.Should().Match<ZeeKayDaConfigurationFailure>(failure =>
                failure.Code == "authenticators.none_declared" &&
                failure.Message.Contains(TokenEndpointAuthMethods.None));
    }

    // ── Overlapping declarations ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Verify_fails_when_two_authenticators_declare_the_same_method()
    {
        var failures = await VerifyAsync(
            [TokenEndpointAuthMethods.ClientSecretBasic],
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic),
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic));

        failures.Should().ContainSingle()
            .Which.Should().Match<ZeeKayDaConfigurationFailure>(failure =>
                failure.Code == "authenticators.method_overlap" &&
                failure.Message.Contains(TokenEndpointAuthMethods.ClientSecretBasic));
    }

    // ── Uncovered server method ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Verify_fails_when_server_advertises_a_method_with_no_registered_authenticator()
    {
        // Server also advertises ClientSecretPost but nothing handles it.
        var failures = await VerifyAsync(
            [TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.ClientSecretPost],
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic));

        failures.Should().ContainSingle()
            .Which.Should().Match<ZeeKayDaConfigurationFailure>(failure =>
                failure.Code == "authenticators.method_uncovered" &&
                failure.Message.Contains(TokenEndpointAuthMethods.ClientSecretPost));
    }

    [Fact]
    public async Task Verify_fails_when_no_authenticators_are_registered_and_server_requires_a_method()
    {
        var failures = await VerifyAsync([TokenEndpointAuthMethods.ClientSecretBasic]);

        failures.Should().ContainSingle()
            .Which.Code.Should().Be("authenticators.method_uncovered");
    }

    [Fact]
    public async Task Verify_reports_a_method_advertised_twice_as_uncovered_once()
    {
        var failures = await VerifyAsync(
            [TokenEndpointAuthMethods.ClientSecretPost, TokenEndpointAuthMethods.ClientSecretPost]);

        failures.Should().ContainSingle();
    }

    // ── Authenticator does not over-advertise ─────────────────────────────────────────────────────

    [Fact]
    public async Task Verify_succeeds_when_authenticator_declares_method_not_in_server_AuthMethodsSupported()
    {
        // An authenticator may declare methods the server does not advertise — coverage validation
        // only checks that every advertised server method has exactly one authenticator; it does
        // not require that every authenticator method is in AuthMethodsSupported.
        var failures = await VerifyAsync(
            [TokenEndpointAuthMethods.ClientSecretBasic],
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.ClientSecretPost));

        failures.Should().BeEmpty();
    }

    // ── DI construction failure ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task An_authenticator_that_fails_to_construct_is_not_swallowed()
    {
        // The startup runner reports an exception from a check as a failure naming its type, with
        // the exception as the root cause. Catching it here instead would skip the coverage check
        // and leave the host to start with an authenticator it cannot build.
        var services = new ServiceCollection();
        services.AddSingleton<IClientAuthenticator, BrokenAuthenticator>();

        var act = () => VerifyAsync(services, [TokenEndpointAuthMethods.ClientSecretBasic]);

        await act.Should().ThrowAsync<InvalidOperationException>();
    }

    // ── Not part of options resolution ────────────────────────────────────────────────────────────

    [Fact]
    public void Reading_the_server_options_constructs_no_client_authenticator()
    {
        // As an options validator this check made the first read of the server options build every
        // authenticator — and with it the secret hasher's startup work — inside whatever happened
        // to read the options first.
        var constructed = false;
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");
        services.AddSingleton<IClientRepository>(_ =>
            throw new InvalidOperationException("Only its registration is checked in this test."));
        services.AddSingleton<IClientAuthenticator>(_ =>
        {
            constructed = true;
            return new FakeAuthenticator("private_key_jwt");
        });
        using var provider = services.BuildServiceProvider();

        _ = provider.GetRequiredService<IOptions<AuthorizationServerOptions>>().Value;

        constructed.Should().BeFalse();
    }

    [Fact]
    public void AddZeeKayDaAuth_registers_the_coverage_check_as_a_startup_activator()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");

        services.Should().ContainSingle(descriptor =>
            descriptor.ImplementationType == typeof(AuthenticatorCoverageValidator))
            .Which.ServiceType.Should().Be(typeof(IStartupActivator));
    }
}
