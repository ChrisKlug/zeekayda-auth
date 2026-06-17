using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

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
    /// during construction, which exercises the validator's catch-and-skip path.
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

    private static AuthenticatorCoverageValidator CreateValidator(
        params IClientAuthenticator[] authenticators)
    {
        var services = new ServiceCollection();
        foreach (var a in authenticators)
            services.AddSingleton(a);
        return new AuthenticatorCoverageValidator(services.BuildServiceProvider());
    }

    private static AuthorizationServerOptions CreateOptions(params string[] methods)
    {
        var options = new AuthorizationServerOptions();
        options.TokenEndpoint.AuthMethodsSupported = [.. methods];
        return options;
    }

    // ── Happy path ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_succeeds_when_all_server_methods_are_covered_by_registered_authenticators()
    {
        var validator = CreateValidator(
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic));

        var result = validator.Validate(null,
            CreateOptions(TokenEndpointAuthMethods.ClientSecretBasic));

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_when_none_is_in_server_methods_without_a_matching_authenticator()
    {
        // "none" is always covered by the composite fallback — no authenticator needed.
        var validator = CreateValidator(
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic));

        var result = validator.Validate(null,
            CreateOptions(TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.None));

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_when_multiple_authenticators_each_cover_distinct_methods()
    {
        var validator = CreateValidator(
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic),
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretPost));

        var result = validator.Validate(null,
            CreateOptions(
                TokenEndpointAuthMethods.ClientSecretBasic,
                TokenEndpointAuthMethods.ClientSecretPost));

        result.Succeeded.Should().BeTrue();
    }

    // ── Whitespace in method string ───────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("client_secret_basic ")]   // trailing space
    [InlineData(" client_secret_basic")]   // leading space
    [InlineData(" client_secret_basic ")]  // both
    [InlineData("client_secret_post ")]    // trailing space on a different known method
    [InlineData(" none")]                  // leading space on the reserved method
    public void Validate_fails_when_authenticator_declares_method_with_surrounding_whitespace(
        string methodWithWhitespace)
    {
        var validator = CreateValidator(
            new FakeAuthenticator(methodWithWhitespace));

        var result = validator.Validate(null,
            CreateOptions(TokenEndpointAuthMethods.ClientSecretBasic));

        result.Succeeded.Should().BeFalse();
        result.FailureMessage.Should().ContainEquivalentOf("whitespace");
    }

    // ── Non-canonical casing ──────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("Client_Secret_Basic")]    // title-case
    [InlineData("CLIENT_SECRET_BASIC")]    // upper-case
    [InlineData("CLIENT_SECRET_POST")]     // upper-case on a different known method
    [InlineData("Client_Secret_Post")]     // title-case on a different known method
    [InlineData("NONE")]                   // upper-case on the reserved method
    public void Validate_fails_when_authenticator_declares_known_method_with_wrong_casing(
        string methodWithWrongCasing)
    {
        var validator = CreateValidator(
            new FakeAuthenticator(methodWithWrongCasing));

        var result = validator.Validate(null,
            CreateOptions(TokenEndpointAuthMethods.ClientSecretBasic));

        result.Succeeded.Should().BeFalse();
        result.FailureMessage.Should().MatchRegex("(?i)canonical|casing");
    }

    // ── none reserved ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_an_authenticator_declares_none()
    {
        var validator = CreateValidator(
            new FakeAuthenticator(TokenEndpointAuthMethods.None));

        var result = validator.Validate(null,
            CreateOptions(TokenEndpointAuthMethods.None));

        result.Succeeded.Should().BeFalse();
        result.FailureMessage.Should().Contain(TokenEndpointAuthMethods.None);
    }

    // ── Overlapping declarations ───────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_two_authenticators_declare_the_same_method()
    {
        var validator = CreateValidator(
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic),
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic));

        var result = validator.Validate(null,
            CreateOptions(TokenEndpointAuthMethods.ClientSecretBasic));

        result.Succeeded.Should().BeFalse();
        result.FailureMessage.Should().Contain(TokenEndpointAuthMethods.ClientSecretBasic);
    }

    // ── Uncovered server method ────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_server_advertises_a_method_with_no_registered_authenticator()
    {
        var validator = CreateValidator(
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic));

        // Server also advertises ClientSecretPost but nothing handles it.
        var result = validator.Validate(null,
            CreateOptions(
                TokenEndpointAuthMethods.ClientSecretBasic,
                TokenEndpointAuthMethods.ClientSecretPost));

        result.Succeeded.Should().BeFalse();
        result.FailureMessage.Should().Contain(TokenEndpointAuthMethods.ClientSecretPost);
    }

    [Fact]
    public void Validate_fails_when_no_authenticators_are_registered_and_server_requires_a_method()
    {
        var validator = CreateValidator();

        var result = validator.Validate(null,
            CreateOptions(TokenEndpointAuthMethods.ClientSecretBasic));

        result.Succeeded.Should().BeFalse();
    }

    // ── Authenticator does not over-advertise ─────────────────────────────────────────────────────

    [Fact]
    public void Validate_succeeds_when_authenticator_declares_method_not_in_server_AuthMethodsSupported()
    {
        // An authenticator may declare methods the server does not advertise — coverage validation
        // only checks that every advertised server method has exactly one authenticator; it does
        // not require that every authenticator method is in AuthMethodsSupported.
        var validator = CreateValidator(
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic, TokenEndpointAuthMethods.ClientSecretPost));

        var result = validator.Validate(null,
            CreateOptions(TokenEndpointAuthMethods.ClientSecretBasic));

        result.Succeeded.Should().BeTrue();
    }

    // ── DI construction failure ───────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_returns_Skip_when_resolving_IClientAuthenticator_throws()
    {
        // If a registered IClientAuthenticator has an unsatisfied constructor dependency,
        // GetServices<IClientAuthenticator>() throws during enumeration. The validator must
        // catch the exception and return Skip so that the root-cause DI error surfaces instead.
        var services = new ServiceCollection();
        services.AddSingleton<IClientAuthenticator, BrokenAuthenticator>();
        var validator = new AuthenticatorCoverageValidator(services.BuildServiceProvider());

        var result = validator.Validate(null,
            CreateOptions(TokenEndpointAuthMethods.ClientSecretBasic));

        result.Skipped.Should().BeTrue();
    }
}
