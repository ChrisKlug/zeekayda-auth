#pragma warning disable ZKD001 // Tests exercise the experimental IdTokenClaims / AccessTokenClaims API by design.
using ZeeKayDa.Auth.Discovery;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Tests.Discovery;

public sealed class DiscoveryDocumentProviderTests
{
    private static async Task<OpenIdConfigurationDocument> GetDocumentAsync(
        AuthorizationServerOptions options,
        IScopeRepository? scopeRepository = null)
    {
        var optionsWrapper = Microsoft.Extensions.Options.Options.Create(options);
        var provider = new DiscoveryDocumentProvider(
            optionsWrapper,
            scopeRepository ?? new InMemoryScopeRepository(StandardScopes.All));
        return await provider.GetDocumentAsync(TestContext.Current.CancellationToken);
    }

    // ── Issuer passthrough (RFC 9207 §4) ─────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocument_returns_Issuer_exactly_as_configured()
    {
        const string issuer = "https://auth.example.com";

        var doc = await GetDocumentAsync(new AuthorizationServerOptions { Issuer = issuer });

        doc.Issuer.Should().Be(issuer);
    }

    // ── URI derivation — root issuer (no path) ────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocument_derives_AuthorizationEndpoint_for_root_Issuer()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        doc.AuthorizationEndpoint.Should().Be("https://auth.example.com/connect/authorize");
    }

    [Fact]
    public async Task GetDocument_derives_TokenEndpoint_for_root_Issuer()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        doc.TokenEndpoint.Should().Be("https://auth.example.com/connect/token");
    }

    [Fact]
    public async Task GetDocument_derives_JwksUri_for_root_Issuer()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        doc.JwksUri.Should().Be("https://auth.example.com/connect/jwks");
    }

    // ── URI derivation — path-bearing issuer ─────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocument_derives_AuthorizationEndpoint_under_Issuer_path_for_path_bearing_Issuer()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1",
        });

        doc.AuthorizationEndpoint.Should().Be("https://auth.example.com/tenant1/connect/authorize");
    }

    [Fact]
    public async Task GetDocument_derives_TokenEndpoint_under_Issuer_path_for_path_bearing_Issuer()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1",
        });

        doc.TokenEndpoint.Should().Be("https://auth.example.com/tenant1/connect/token");
    }

    [Fact]
    public async Task GetDocument_derives_JwksUri_under_Issuer_path_for_path_bearing_Issuer()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1",
        });

        doc.JwksUri.Should().Be("https://auth.example.com/tenant1/connect/jwks");
    }

    // ── Explicit URI overrides ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocument_uses_override_not_derived_value_when_explicit_AuthorizationEndpoint_is_configured()
    {
        const string explicitUri = "https://other.example.com/custom/authorize";

        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { Uri = explicitUri },
        });

        doc.AuthorizationEndpoint.Should().Be(explicitUri);
    }

    [Fact]
    public async Task GetDocument_uses_override_not_derived_value_when_explicit_TokenEndpoint_is_configured()
    {
        const string explicitUri = "https://other.example.com/custom/token";

        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = { Uri = explicitUri },
        });

        doc.TokenEndpoint.Should().Be(explicitUri);
    }

    [Fact]
    public async Task GetDocument_uses_override_not_derived_value_when_explicit_JwksUri_is_configured()
    {
        const string explicitUri = "https://other.example.com/custom/jwks";

        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            JwksEndpoint = { Uri = explicitUri },
        });

        doc.JwksUri.Should().Be(explicitUri);
    }

    // ── Collection fields ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocument_includes_default_collection_values_when_using_default_options()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        doc.ResponseTypesSupported.Should().ContainSingle().Which.Should().Be(ResponseType.Code);
        doc.ScopesSupported.Should().Equal(StandardScopes.All.Select(scope => scope.Name));
        doc.ResponseModesSupported.Should().ContainSingle().Which.Should().Be(ResponseMode.Query);
        doc.GrantTypesSupported.Should().ContainSingle().Which.Should().Be(GrantType.AuthorizationCode);
        doc.TokenEndpointAuthMethodsSupported.Should().ContainSingle().Which.Should().Be(TokenEndpointAuthMethods.ClientSecretBasic);
        doc.SubjectTypesSupported.Should().ContainSingle().Which.Should().Be("public");
        doc.IdTokenSigningAlgValuesSupported.Should().ContainSingle().Which.Should().Be(SigningAlgorithm.RS256);
    }

    [Fact]
    public async Task GetDocument_uses_configured_values_for_custom_collections()
    {
        var scopeRepository = new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = StandardScopes.OpenId.Name },
            new ScopeDefinition { Name = StandardScopes.Profile.Name },
        ]);

        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            Response =
            {
                TypesSupported = [ResponseType.Code],
                ModesSupported = [ResponseMode.Query, ResponseMode.FormPost],
            },
            GrantTypesSupported = [GrantType.AuthorizationCode, GrantType.RefreshToken],
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethods.ClientSecretBasic, "tls_client_auth"] },
            IdToken = { SigningAlgValuesSupported = [SigningAlgorithm.RS256, SigningAlgorithm.PS256] },
        }, scopeRepository);

        doc.ResponseTypesSupported.Should().Equal(ResponseType.Code);
        doc.ScopesSupported.Should().Equal(StandardScopes.OpenId.Name, StandardScopes.Profile.Name);
        doc.ResponseModesSupported.Should().Equal(ResponseMode.Query, ResponseMode.FormPost);
        doc.GrantTypesSupported.Should().Equal(GrantType.AuthorizationCode, GrantType.RefreshToken);
        doc.TokenEndpointAuthMethodsSupported.Should().Equal(
            TokenEndpointAuthMethods.ClientSecretBasic,
            "tls_client_auth");
        doc.IdTokenSigningAlgValuesSupported.Should().Equal(SigningAlgorithm.RS256, SigningAlgorithm.PS256);
    }

    [Fact]
    public async Task GetDocument_uses_repository_scopes_for_discovery()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition
            {
                Name = StandardScopes.OpenId.Name,
                IdTokenClaims = ["sub"],
                AccessTokenClaims = ["scope"],
            },
            new ScopeDefinition
            {
                Name = StandardScopes.Profile.Name,
                IdTokenClaims = ["name", "family_name"],
                AccessTokenClaims = ["name"],
            },
        ]);

        var doc = await GetDocumentAsync(
            new AuthorizationServerOptions
            {
                Issuer = "https://auth.example.com",
            },
            repository);

        doc.ScopesSupported.Should().Equal(StandardScopes.OpenId.Name, StandardScopes.Profile.Name);
    }

    [Fact]
    public async Task GetDocument_excludes_non_discoverable_scopes_from_ScopeRepository()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = StandardScopes.OpenId.Name },
            new ScopeDefinition
            {
                Name = "internal.admin",
                IsDiscoverable = false,
                AccessTokenClaims = ["scope"],
            },
        ]);

        var doc = await GetDocumentAsync(
            new AuthorizationServerOptions
            {
                Issuer = "https://auth.example.com",
            },
            repository);

        doc.ScopesSupported.Should().Equal(StandardScopes.OpenId.Name);
    }

    // ── Cancellation contract ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocumentAsync_throws_via_InMemoryScopeRepository_when_token_is_already_cancelled()
    {
        var options = Microsoft.Extensions.Options.Options.Create(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" });
        var provider = new DiscoveryDocumentProvider(options, new InMemoryScopeRepository(StandardScopes.All));

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = async () => await provider.GetDocumentAsync(cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task GetDocumentAsync_propagates_CancellationToken_to_ScopeRepository()
    {
        var options = Microsoft.Extensions.Options.Options.Create(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" });
        var capturingRepository = new CapturingScopeRepository();
        var provider = new DiscoveryDocumentProvider(options, capturingRepository);

        using var cts = new CancellationTokenSource();

        await provider.GetDocumentAsync(cts.Token);

        capturingRepository.ObservedToken.Should().Be(cts.Token);
    }

    [Fact]
    public async Task GetDocumentAsync_surfaces_exception_when_ScopeRepository_cancels()
    {
        var options = Microsoft.Extensions.Options.Options.Create(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" });
        var provider = new DiscoveryDocumentProvider(options, new ThrowingScopeRepository());

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = async () => await provider.GetDocumentAsync(cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    private sealed class CapturingScopeRepository : IScopeRepository
    {
        public CancellationToken ObservedToken { get; private set; }

        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
        {
            ObservedToken = cancellationToken;
            return ValueTask.FromResult<IReadOnlyCollection<ScopeDefinition>>([]);
        }
    }

    private sealed class ThrowingScopeRepository : IScopeRepository
    {
        public ValueTask<IReadOnlyCollection<ScopeDefinition>> GetScopesAsync(CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult<IReadOnlyCollection<ScopeDefinition>>([]);
        }
    }

    // ── CodeChallengeMethodsSupported ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocument_omits_CodeChallengeMethodsSupported_field_when_null()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { CodeChallengeMethodsSupported = null },
        });

        doc.CodeChallengeMethodsSupported.Should().BeNull();
    }

    [Fact]
    public async Task GetDocument_publishes_CodeChallengeMethodsSupported_field_when_S256_is_configured()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = { CodeChallengeMethodsSupported = [CodeChallengeMethod.S256] },
        });

        doc.CodeChallengeMethodsSupported.Should().ContainSingle()
            .Which.Should().Be(CodeChallengeMethod.S256);
    }
}
