using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.ClientAuthentication;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.ClientAuthentication;

public sealed class ClientAuthenticatorActivatorTests
{
    // ── Fake authenticator ────────────────────────────────────────────────────────────────────────

    private sealed class FakeAuthenticator : IClientAuthenticator
    {
        public FakeAuthenticator(params string[] methods) =>
            AuthenticationMethods = new HashSet<string>(methods, StringComparer.Ordinal);

        public IReadOnlySet<string> AuthenticationMethods { get; }

        public ClientAuthenticatorMatch CanHandle(TokenRequestContext context) => ClientAuthenticatorMatch.None;

        public Task<ClientAuthenticationResult> AuthenticateAsync(
            ClientAuthenticationContext context, CancellationToken ct) =>
            Task.FromResult(ClientAuthenticationResult.NotValid());
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

        public ClientAuthenticatorMatch CanHandle(TokenRequestContext context) => ClientAuthenticatorMatch.None;

        public Task<ClientAuthenticationResult> AuthenticateAsync(
            ClientAuthenticationContext context, CancellationToken ct) =>
            Task.FromResult(ClientAuthenticationResult.NotValid());
    }

    /// <summary>Breaks the interface's non-null contract, as a careless implementation can.</summary>
    private sealed class NullMethodsAuthenticator(IReadOnlySet<string> methods) : IClientAuthenticator
    {
        public IReadOnlySet<string> AuthenticationMethods => methods;

        public ClientAuthenticatorMatch CanHandle(TokenRequestContext context) => ClientAuthenticatorMatch.None;

        public Task<ClientAuthenticationResult> AuthenticateAsync(
            ClientAuthenticationContext context, CancellationToken ct) =>
            Task.FromResult(ClientAuthenticationResult.NotValid());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private static async Task<IReadOnlyList<ZeeKayDaConfigurationFailure>> VerifyAsync(
        params IClientAuthenticator[] authenticators)
    {
        var services = new ServiceCollection();
        foreach (var a in authenticators)
            services.AddSingleton(a);

        return await VerifyAsync(services);
    }

    private static async Task<IReadOnlyList<ZeeKayDaConfigurationFailure>> VerifyAsync(ServiceCollection services)
    {
        services.AddSingleton(sp => new RegisteredAuthenticators(sp.GetServices<IClientAuthenticator>()));

        await using var provider = services.BuildServiceProvider();
        var context = new StartupVerificationContext();

        await new ClientAuthenticatorActivator(provider)
            .VerifyAsync(context, TestContext.Current.CancellationToken);

        return context.Failures;
    }

    // ── Happy path ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Verify_succeeds_when_an_authenticator_declares_well_formed_methods()
    {
        var failures = await VerifyAsync(new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic));

        failures.Should().BeEmpty();
    }

    [Fact]
    public async Task Verify_succeeds_when_multiple_authenticators_each_cover_distinct_methods()
    {
        var failures = await VerifyAsync(
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
            new FakeAuthenticator(methodWithWhitespace));

        failures.Should().Contain(failure =>
            failure.Code == "authenticators.method_whitespace" &&
            failure.Message.Contains("whitespace"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("client\u0001secret")]
    public async Task Verify_fails_when_authenticator_declares_a_blank_or_control_character_method(string method)
    {
        var failures = await VerifyAsync(new FakeAuthenticator(method));

        failures.Should().ContainSingle()
            .Which.Code.Should().Be("authenticators.method_malformed");
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
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic),
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic));

        failures.Should().ContainSingle()
            .Which.Should().Match<ZeeKayDaConfigurationFailure>(failure =>
                failure.Code == "authenticators.method_overlap" &&
                failure.Message.Contains(TokenEndpointAuthMethods.ClientSecretBasic));
    }

    // ── An authenticator breaking the non-null contract ───────────────────────────────────────────

    [Fact]
    public async Task Verify_fails_naming_an_authenticator_whose_AuthenticationMethods_is_null()
    {
        var failures = await VerifyAsync(new NullMethodsAuthenticator(null!));

        failures.Should().ContainSingle()
            .Which.Should().Match<ZeeKayDaConfigurationFailure>(failure =>
                failure.Code == "authenticators.method_null" &&
                failure.Message.Contains(nameof(NullMethodsAuthenticator)));
    }

    [Fact]
    public async Task Verify_fails_naming_an_authenticator_that_declares_a_null_method()
    {
        var failures = await VerifyAsync(new NullMethodsAuthenticator(
            new HashSet<string>(StringComparer.Ordinal) { TokenEndpointAuthMethods.ClientSecretBasic, null! }));

        failures.Should().ContainSingle()
            .Which.Code.Should().Be("authenticators.method_null");
    }

    // ── DI construction failure ───────────────────────────────────────────────────────────────────

    [Fact]
    public async Task An_authenticator_that_fails_to_construct_is_not_swallowed()
    {
        // The startup runner reports an exception from a check as a failure naming its type, with
        // the exception as the root cause. Catching it here instead would leave the host to start
        // with an authenticator it cannot build.
        var services = new ServiceCollection();
        services.AddSingleton<IClientAuthenticator, BrokenAuthenticator>();

        var act = () => VerifyAsync(services);

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
    public void AddZeeKayDaAuth_registers_the_declaration_check_as_a_startup_activator()
    {
        var services = new ServiceCollection();

        services.AddZeeKayDaAuth(options => options.Issuer = "https://auth.example.com");

        services.Should().ContainSingle(descriptor =>
            descriptor.ImplementationType == typeof(ClientAuthenticatorActivator))
            .Which.ServiceType.Should().Be(typeof(IStartupActivator));
    }
}
