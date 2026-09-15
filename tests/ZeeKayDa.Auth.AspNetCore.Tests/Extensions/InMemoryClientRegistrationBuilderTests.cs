using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Clients;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class InMemoryClientRegistrationBuilderTests
{
    private static readonly string[] RedirectUris = ["https://app.example.com/cb"];
    private static readonly string[] Scopes = ["openid"];

    private readonly InMemoryClientRegistrationOptions _options = new();
    private readonly InMemoryClientRegistrationBuilder _builder;

    public InMemoryClientRegistrationBuilderTests()
        => _builder = new InMemoryClientRegistrationBuilder(_options);

    // ── AddPublic ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AddPublic_applies_the_configured_settings()
    {
        _builder.AddPublic("spa", RedirectUris, [], Scopes, options =>
        {
            options.RequireConsent = false;
            options.DisplayName = "Our SPA";
            options.AllowedGrantTypes.Add(GrantType.RefreshToken);
            options.AccessTokenLifetime = TimeSpan.FromMinutes(5);
            options.AdditionalIdTokenClaims.Add("department");
        });

        var registration = SinglePublic();
        registration.RequireConsent.Should().BeFalse();
        registration.DisplayName.Should().Be("Our SPA");
        registration.AllowedGrantTypes.Should().BeEquivalentTo([GrantType.AuthorizationCode, GrantType.RefreshToken]);
        registration.AccessTokenLifetime.Should().Be(TimeSpan.FromMinutes(5));
        registration.AdditionalIdTokenClaims.Should().Equal("department");
    }

    [Fact]
    public void AddPublic_keeps_the_client_public_whatever_the_callback_sets()
    {
        _builder.AddPublic("spa", RedirectUris, [], Scopes, options => options.RequireConsent = false);

        var registration = SinglePublic();
        registration.ClientId.Should().Be("spa");
        registration.IsPublic.Should().BeTrue();
        registration.Credentials.Should().BeEmpty();
        registration.AllowedTokenEndpointAuthMethods.Should().Equal(TokenEndpointAuthMethods.None);
        registration.RedirectUris.Should().BeEquivalentTo(RedirectUris);
        registration.AllowedScopes.Should().BeEquivalentTo(Scopes);
    }

    [Fact]
    public void AddPublic_with_a_callback_that_changes_nothing_registers_the_same_client_as_without_one()
    {
        _builder.AddPublic("spa", RedirectUris, [], Scopes);
        _builder.AddPublic("spa", RedirectUris, [], Scopes, _ => { });

        _options.PreBuilt[1].Should().BeEquivalentTo(_options.PreBuilt[0]);
    }

    // ── AddConfidential ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AddConfidential_applies_the_configured_settings()
    {
        _builder.AddConfidential("web", "very-secret", RedirectUris, [], Scopes, options =>
        {
            options.RequireConsent = false;
            options.AllowNonceInsteadOfPkce = true;
            options.AllowedTokenEndpointAuthMethods.Clear();
            options.AllowedTokenEndpointAuthMethods.Add(TokenEndpointAuthMethods.ClientSecretPost);
        });

        var registration = SinglePending().Registration;
        registration.RequireConsent.Should().BeFalse();
        registration.AllowNonceInsteadOfPkce.Should().BeTrue();
        registration.AllowedTokenEndpointAuthMethods.Should().Equal(TokenEndpointAuthMethods.ClientSecretPost);
    }

    [Fact]
    public void AddConfidential_keeps_the_client_confidential_and_its_secret_pending_hashing()
    {
        _builder.AddConfidential("web", "very-secret", RedirectUris, [], Scopes, options => options.RequireConsent = false);

        var pending = SinglePending();
        pending.PlaintextSecret.Should().Be("very-secret");
        pending.Registration.ClientId.Should().Be("web");
        pending.Registration.IsPublic.Should().BeFalse();
        pending.Registration.Credentials.Should().BeEmpty();
    }

    [Fact]
    public void AddConfidential_with_a_callback_that_changes_nothing_registers_the_same_client_as_without_one()
    {
        _builder.AddConfidential("web", "very-secret", RedirectUris, [], Scopes);
        _builder.AddConfidential("web", "very-secret", RedirectUris, [], Scopes, _ => { });

        _options.Pending[1].Registration.Should().BeEquivalentTo(_options.Pending[0].Registration);
    }

    // ── Options defaults and ownership ────────────────────────────────────────────────────────────

    [Fact]
    public void ConfidentialClientOptions_start_with_the_defaults_of_a_registration_that_sets_nothing()
    {
        ConfidentialClientOptions? seen = null;

        _builder.AddConfidential("web", "very-secret", RedirectUris, [], Scopes, options => seen = options);

        seen!.RequireConsent.Should().BeTrue();
        seen.AllowNonceInsteadOfPkce.Should().BeFalse();
        seen.AllowedGrantTypes.Should().Equal(GrantType.AuthorizationCode);
        seen.AllowedTokenEndpointAuthMethods.Should().Equal(TokenEndpointAuthMethods.ClientSecretBasic);
        seen.AllowedSigningAlgorithms.Should().BeEmpty();
        seen.DisplayName.Should().BeNull();
    }

    [Fact]
    public void Changing_the_options_after_the_callback_returns_does_not_change_the_registration()
    {
        PublicClientOptions? kept = null;
        _builder.AddPublic("spa", RedirectUris, [], Scopes, options => kept = options);

        kept!.RequireConsent = false;
        kept.AllowedGrantTypes.Add(GrantType.RefreshToken);
        kept.AdditionalAccessTokenClaims.Add("department");

        var registration = SinglePublic();
        registration.RequireConsent.Should().BeTrue();
        registration.AllowedGrantTypes.Should().Equal(GrantType.AuthorizationCode);
        registration.AdditionalAccessTokenClaims.Should().BeEmpty();
    }

    // ── AllowedSigningAlgorithms ──────────────────────────────────────────────────────────────────

    [Fact]
    public void AllowedSigningAlgorithms_left_empty_registers_null_so_the_client_inherits_the_server_set()
    {
        _builder.AddPublic("spa", RedirectUris, [], Scopes, options => options.RequireConsent = false);

        SinglePublic().AllowedSigningAlgorithms.Should().BeNull();
    }

    [Fact]
    public void AllowedSigningAlgorithms_set_on_the_options_are_registered()
    {
        _builder.AddPublic("spa", RedirectUris, [], Scopes,
            options => options.AllowedSigningAlgorithms.Add(SigningAlgorithm.ES256));

        SinglePublic().AllowedSigningAlgorithms.Should().Equal(SigningAlgorithm.ES256);
    }

    private IClientRegistration SinglePublic()
        => _options.PreBuilt.Should().ContainSingle().Which;

    private PendingConfidentialClientSpec SinglePending()
        => _options.Pending.Should().ContainSingle().Which;
}
