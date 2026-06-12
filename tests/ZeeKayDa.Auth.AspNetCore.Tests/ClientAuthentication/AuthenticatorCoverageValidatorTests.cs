using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;
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

    // ── Helpers ───────────────────────────────────────────────────────────────────────────────────

    private static AuthenticatorCoverageValidator CreateValidator(
        params IClientAuthenticator[] authenticators)
    {
        var services = new ServiceCollection();
        foreach (var a in authenticators)
            services.AddSingleton(a);
        return new AuthenticatorCoverageValidator(services.BuildServiceProvider());
    }

    private static AuthorizationServerOptions CreateOptions(params TokenEndpointAuthMethod[] methods)
    {
        var options = new AuthorizationServerOptions();
        options.TokenEndpoint.AuthMethodsSupported = new List<TokenEndpointAuthMethod>(methods);
        return options;
    }

    // ── Happy path ────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_succeeds_when_all_server_methods_are_covered_by_registered_authenticators()
    {
        var validator = CreateValidator(
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic));

        var result = validator.Validate(null,
            CreateOptions(TokenEndpointAuthMethod.ClientSecretBasic));

        result.Succeeded.Should().BeTrue();
    }

    [Fact]
    public void Validate_succeeds_when_none_is_in_server_methods_without_a_matching_authenticator()
    {
        // "none" is always covered by the composite fallback — no authenticator needed.
        var validator = CreateValidator(
            new FakeAuthenticator(TokenEndpointAuthMethods.ClientSecretBasic));

        var result = validator.Validate(null,
            CreateOptions(TokenEndpointAuthMethod.ClientSecretBasic, TokenEndpointAuthMethod.None));

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
                TokenEndpointAuthMethod.ClientSecretBasic,
                TokenEndpointAuthMethod.ClientSecretPost));

        result.Succeeded.Should().BeTrue();
    }

    // ── none reserved ─────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Validate_fails_when_an_authenticator_declares_none()
    {
        var validator = CreateValidator(
            new FakeAuthenticator(TokenEndpointAuthMethods.None));

        var result = validator.Validate(null,
            CreateOptions(TokenEndpointAuthMethod.None));

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
            CreateOptions(TokenEndpointAuthMethod.ClientSecretBasic));

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
                TokenEndpointAuthMethod.ClientSecretBasic,
                TokenEndpointAuthMethod.ClientSecretPost));

        result.Succeeded.Should().BeFalse();
        result.FailureMessage.Should().Contain(TokenEndpointAuthMethods.ClientSecretPost);
    }

    [Fact]
    public void Validate_fails_when_no_authenticators_are_registered_and_server_requires_a_method()
    {
        var validator = CreateValidator();

        var result = validator.Validate(null,
            CreateOptions(TokenEndpointAuthMethod.ClientSecretBasic));

        result.Succeeded.Should().BeFalse();
    }
}
