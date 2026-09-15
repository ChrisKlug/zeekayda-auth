using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Clients;
using ZeeKayDa.Auth.Authorization;
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
    public void AddPublic_registers_every_setting_the_callback_changes()
    {
        PublicClientOptions? configured = null;

        _builder.AddPublic("spa", RedirectUris, [], Scopes, options =>
        {
            ChangeEverySharedSetting(options);
            configured = options;
        });

        // Driven by the options' members, so a setting added to the options and not copied fails here.
        SinglePublic().Should().BeEquivalentTo(configured);
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
    public void AddConfidential_registers_every_setting_the_callback_changes()
    {
        ConfidentialClientOptions? configured = null;

        _builder.AddConfidential("web", "very-secret", RedirectUris, [], Scopes, options =>
        {
            ChangeEverySharedSetting(options);
            options.AllowNonceInsteadOfPkce = true;
            options.AllowedTokenEndpointAuthMethods.Clear();
            options.AllowedTokenEndpointAuthMethods.Add(TokenEndpointAuthMethods.ClientSecretPost);
            configured = options;
        });

        // Covers the shared settings as well as the confidential-only ones.
        SinglePending().Registration.Should().BeEquivalentTo(configured);
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

    // ── Every registration setting has an option ──────────────────────────────────────────────────

    // The builder methods set the client's identity themselves; everything else is an option.
    private static readonly string[] SetByTheBuilderMethods =
    [
        nameof(IClientRegistration.ClientId),
        nameof(IClientRegistration.IsPublic),
        nameof(IClientRegistration.Credentials),
        nameof(IClientRegistration.RedirectUris),
        nameof(IClientRegistration.PostLogoutRedirectUris),
        nameof(IClientRegistration.AllowedScopes),
    ];

    private static readonly string[] ConfidentialOnly =
    [
        nameof(ConfidentialClientOptions.AllowNonceInsteadOfPkce),
        nameof(ConfidentialClientOptions.AllowedTokenEndpointAuthMethods),
    ];

    [Fact]
    public void ConfidentialClientOptions_has_a_setting_for_every_registration_member_but_the_identity()
    {
        var options = typeof(ConfidentialClientOptions).GetProperties().Select(p => p.Name);

        options.Should().BeEquivalentTo(RegistrationMembers().Except(SetByTheBuilderMethods, StringComparer.Ordinal));
    }

    [Fact]
    public void PublicClientOptions_has_a_setting_for_every_registration_member_but_the_identity_and_the_confidential_only_ones()
    {
        var options = typeof(PublicClientOptions).GetProperties().Select(p => p.Name);

        options.Should().BeEquivalentTo(RegistrationMembers()
            .Except(SetByTheBuilderMethods.Concat(ConfidentialOnly), StringComparer.Ordinal));
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

    // Moves every shared setting off its default, so a setting the builder fails to copy cannot
    // match the registration by coincidence.
    private static void ChangeEverySharedSetting(ClientOptions options)
    {
        options.DisplayName = "Our app";
        options.RequireConsent = false;
        options.EnableZkdErrorCodes = true;
        options.AllowedGrantTypes.Add(GrantType.RefreshToken);
        options.AllowedResponseTypes.Clear();
        options.AllowedResponseModes.Remove(ResponseMode.Query);
        options.AllowedPromptValues.Add(PromptValue.Login);
        options.AllowedSigningAlgorithms.Add(SigningAlgorithm.ES256);
        options.AccessTokenLifetime = TimeSpan.FromMinutes(5);
        options.IdTokenLifetime = TimeSpan.FromMinutes(2);
        options.AdditionalIdTokenClaims.Add("department");
        options.AdditionalUserInfoClaims.Add("cost_center");
        options.AdditionalAccessTokenClaims.Add("tenant");
    }

    // Type.GetProperties() on an interface does not return inherited members, so the whole
    // implemented-interface set is walked; a member on a new base interface is then caught too.
    private static IEnumerable<string> RegistrationMembers()
        => typeof(IClientRegistration).GetInterfaces()
            .Append(typeof(IClientRegistration))
            .SelectMany(t => t.GetProperties())
            .Select(p => p.Name)
            .Distinct(StringComparer.Ordinal);

    private IClientRegistration SinglePublic()
        => _options.PreBuilt.Should().ContainSingle().Which;

    private PendingConfidentialClientSpec SinglePending()
        => _options.Pending.Should().ContainSingle().Which;
}
