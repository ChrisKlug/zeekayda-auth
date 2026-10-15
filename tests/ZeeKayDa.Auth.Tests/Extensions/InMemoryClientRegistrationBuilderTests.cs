using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Extensions;

public sealed class InMemoryClientRegistrationBuilderTests
{
    private static readonly string[] RedirectUris = ["https://app.example.com/cb"];
    private static readonly string[] Scopes = ["openid"];
    private const string Secret = "very-secret";

    private readonly InMemoryClientRegistrationOptions _options = new();
    private readonly InMemoryClientRegistrationBuilder _builder;

    public InMemoryClientRegistrationBuilderTests()
        => _builder = new InMemoryClientRegistrationBuilder(_options);

    // ── AddPublic ─────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AddPublic_registers_every_setting_the_callback_changes()
    {
        PublicClientOptions? configured = null;

        _builder.AddPublic("spa", options =>
        {
            ChangeEverySharedSetting(options);
            configured = options;
        });

        // Driven by the options' members, so a setting added to the options and not copied fails here.
        SinglePublic().Should().BeEquivalentTo(configured);
    }

    [Fact]
    public void AddPublic_without_a_callback_throws()
    {
        var act = () => _builder.AddPublic("spa", null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("configure");
    }

    [Fact]
    public void AddPublic_keeps_the_client_public_whatever_the_callback_sets()
    {
        _builder.AddPublic("spa", options => WithBasics(options).RequireConsent = false);

        var registration = SinglePublic();
        registration.ClientId.Should().Be("spa");
        registration.IsPublic.Should().BeTrue();
        registration.Secrets.Should().BeEmpty();
        registration.AllowedTokenEndpointAuthMethods.Should().Equal(TokenEndpointAuthMethods.None);
        registration.RedirectUris.Should().BeEquivalentTo(RedirectUris);
        registration.AllowedScopes.Should().BeEquivalentTo(Scopes);
    }

    // ── AddConfidential ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AddConfidential_registers_every_setting_the_callback_changes()
    {
        ConfidentialClientOptions? configured = null;

        _builder.AddConfidential("web", options =>
        {
            ChangeEverySharedSetting(options);
            options.RequirePkce = false;
            options.AllowedTokenEndpointAuthMethods.Add(TokenEndpointAuthMethods.ClientSecretPost);
            configured = options;
        });

        // Covers the shared settings as well as the confidential-only ones. The secret is not a
        // registration member; it travels beside the registration until the repository is built.
        SinglePending().Registration.Should().BeEquivalentTo(configured, compare => compare
            .Excluding(options => options!.Secret)
            .Excluding(options => options!.SecretHash));
    }

    [Fact]
    public void AddConfidential_keeps_the_client_confidential_and_its_secret_pending_hashing()
    {
        _builder.AddConfidential("web", options => WithBasics(options).Secret = Secret);

        var pending = SinglePending();
        pending.PlaintextSecret.Should().Be(Secret);
        pending.SecretHash.Should().BeNull();
        pending.Registration.ClientId.Should().Be("web");
        pending.Registration.IsPublic.Should().BeFalse();
        pending.Registration.Secrets.Should().BeEmpty();
        pending.Registration.RedirectUris.Should().BeEquivalentTo(RedirectUris);
        pending.Registration.AllowedScopes.Should().BeEquivalentTo(Scopes);
    }

    [Fact]
    public void AddConfidential_carries_a_secret_hash_to_the_repository_as_given()
    {
        _builder.AddConfidential("web", options => WithBasics(options).SecretHash = "$2b$12$hash");

        var pending = SinglePending();
        pending.SecretHash.Should().Be("$2b$12$hash");
        pending.PlaintextSecret.Should().BeNull();
    }

    [Fact]
    public void AddConfidential_without_a_callback_throws()
    {
        var act = () => _builder.AddConfidential("web", null!);

        act.Should().Throw<ArgumentNullException>().WithParameterName("configure");
    }

    // ── Options defaults and ownership ────────────────────────────────────────────────────────────

    [Fact]
    public void ConfidentialClientOptions_start_with_the_defaults_of_a_registration_that_sets_nothing()
    {
        ConfidentialClientOptions? seen = null;

        _builder.AddConfidential("web", options => seen = options);

        seen!.RequireConsent.Should().BeTrue();
        seen.SkipLogoutConfirmation.Should().BeFalse();
        seen.RequirePkce.Should().BeTrue();
        seen.AllowedSigningAlgorithms.Should().BeEmpty();
        seen.DisplayName.Should().BeNull();
        seen.InitiateLoginUri.Should().BeNull();
    }

    [Fact]
    public void A_confidential_client_configured_with_client_secret_post_alone_allows_only_client_secret_post()
    {
        _builder.AddConfidential("web", options => WithBasics(options).AllowedTokenEndpointAuthMethods.Add(TokenEndpointAuthMethods.ClientSecretPost));

        SinglePending().Registration.AllowedTokenEndpointAuthMethods.Should().Equal(TokenEndpointAuthMethods.ClientSecretPost);
    }

    [Fact]
    public void A_confidential_client_configured_with_no_auth_method_gets_client_secret_basic()
    {
        _builder.AddConfidential("web", options => WithBasics(options).RequireConsent = false);

        SinglePending().Registration.AllowedTokenEndpointAuthMethods.Should().Equal(TokenEndpointAuthMethods.ClientSecretBasic);
    }

    [Fact]
    public void Every_defaulted_collection_starts_empty_in_the_callback()
    {
        ConfidentialClientOptions? seen = null;

        _builder.AddConfidential("web", options => seen = options);

        seen!.AllowedTokenEndpointAuthMethods.Should().BeEmpty();
        seen.AllowedGrantTypes.Should().BeEmpty();
        seen.AllowedResponseTypes.Should().BeEmpty();
        seen.AllowedResponseModes.Should().BeEmpty();
    }

    [Fact]
    public void A_client_that_names_no_grant_type_gets_the_code_grant_with_its_response_type_and_mode()
    {
        _builder.AddPublic("spa", options => WithBasics(options).RequireConsent = false);

        var registration = SinglePublic();
        registration.AllowedGrantTypes.Should().Equal(GrantType.AuthorizationCode);
        registration.AllowedResponseTypes.Should().Equal(ResponseType.Code);
        registration.AllowedResponseModes.Should().Equal(ResponseMode.Query);
    }

    [Fact]
    public void A_client_credentials_only_client_gets_the_same_response_types_and_modes_as_through_the_record()
    {
        _builder.AddConfidential("service", options => options.AllowedGrantTypes.Add(GrantType.ClientCredentials));

        var registration = SinglePending().Registration;
        var throughRecord = new Client { ClientId = "service", AllowedGrantTypes = registration.AllowedGrantTypes };
        registration.AllowedGrantTypes.Should().Equal(GrantType.ClientCredentials);
        registration.AllowedResponseTypes.Should().BeEquivalentTo(throughRecord.AllowedResponseTypes);
        registration.AllowedResponseModes.Should().BeEquivalentTo(throughRecord.AllowedResponseModes);
    }

    [Fact]
    public void Response_types_and_modes_the_callback_names_are_kept_whatever_the_grant_types()
    {
        _builder.AddConfidential("service", options =>
        {
            options.AllowedGrantTypes.Add(GrantType.ClientCredentials);
            options.AllowedResponseTypes.Add(ResponseType.Code);
            options.AllowedResponseModes.Add(ResponseMode.Query);
        });

        var registration = SinglePending().Registration;
        registration.AllowedResponseTypes.Should().Equal(ResponseType.Code);
        registration.AllowedResponseModes.Should().Equal(ResponseMode.Query);
    }

    [Fact]
    public void Changing_the_options_after_the_callback_returns_does_not_change_the_registration()
    {
        PublicClientOptions? kept = null;
        _builder.AddPublic("spa", options => kept = options);

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
        nameof(IClientWithCredentials.ClientId),
        nameof(IClientWithCredentials.IsPublic),
        nameof(IClientWithCredentials.Secrets),
    ];

    // The options' form of Secrets: one secret, in plaintext or already hashed.
    private static readonly string[] SecretOptions =
    [
        nameof(ConfidentialClientOptions.Secret),
        nameof(ConfidentialClientOptions.SecretHash),
    ];

    private static readonly string[] ConfidentialOnly =
    [
        nameof(ConfidentialClientOptions.RequirePkce),
        nameof(ConfidentialClientOptions.AllowedTokenEndpointAuthMethods),
    ];

    [Fact]
    public void ConfidentialClientOptions_has_a_setting_for_every_registration_member_but_the_identity()
    {
        var options = typeof(ConfidentialClientOptions).GetProperties().Select(p => p.Name);

        options.Should().BeEquivalentTo(RegistrationMembers()
            .Except(SetByTheBuilderMethods, StringComparer.Ordinal)
            .Concat(SecretOptions));
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
        _builder.AddPublic("spa", options => WithBasics(options).RequireConsent = false);

        SinglePublic().AllowedSigningAlgorithms.Should().BeNull();
    }

    [Fact]
    public void AllowedSigningAlgorithms_set_on_the_options_are_registered()
    {
        _builder.AddPublic("spa", options => WithBasics(options).AllowedSigningAlgorithms.Add(SigningAlgorithm.ES256));

        SinglePublic().AllowedSigningAlgorithms.Should().Equal(SigningAlgorithm.ES256);
    }

    // Moves every shared setting off its default, so a setting the builder fails to copy cannot
    // match the registration by coincidence.
    private static void ChangeEverySharedSetting(ClientOptions options)
    {
        WithBasics(options);
        options.PostLogoutRedirectUris.Add("https://app.example.com/signed-out");
        options.DisplayName = "Our app";
        options.InitiateLoginUri = "https://app.example.com/login";
        options.RequireConsent = false;
        options.SkipLogoutConfirmation = true;
        options.EnableZkdErrorCodes = true;
        options.AllowedGrantTypes.Add(GrantType.AuthorizationCode);
        options.AllowedGrantTypes.Add(GrantType.RefreshToken);
        options.AllowedResponseTypes.Add(ResponseType.Code);
        options.AllowedResponseModes.Add(ResponseMode.Query);
        options.AllowedPromptValues.Add(PromptValue.Login);
        options.AllowedSigningAlgorithms.Add(SigningAlgorithm.ES256);
        options.AccessTokenLifetime = TimeSpan.FromMinutes(5);
        options.IdTokenLifetime = TimeSpan.FromMinutes(2);
        options.AdditionalIdTokenClaims.Add("department");
        options.AdditionalUserInfoClaims.Add("cost_center");
        options.AdditionalAccessTokenClaims.Add("tenant");
    }

    private static T WithBasics<T>(T options)
        where T : ClientOptions
    {
        options.RedirectUris.UnionWith(RedirectUris);
        options.AllowedScopes.UnionWith(Scopes);
        return options;
    }

    // Type.GetProperties() on an interface does not return inherited members, so the whole
    // implemented-interface set is walked; a member on a new base interface is then caught too.
    private static IEnumerable<string> RegistrationMembers()
        => typeof(IClientWithCredentials).GetInterfaces()
            .Append(typeof(IClientWithCredentials))
            .SelectMany(t => t.GetProperties())
            .Select(p => p.Name)
            .Distinct(StringComparer.Ordinal);

    private IClientWithCredentials SinglePublic()
        => _options.PreBuilt.Should().ContainSingle().Which;

    private PendingConfidentialClientSpec SinglePending()
        => _options.Pending.Should().ContainSingle().Which;
}
