using Microsoft.Extensions.Options;
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
            scopeRepository ?? new DefaultScopeRepository());
        return await provider.GetDocumentAsync(TestContext.Current.CancellationToken);
    }

    // ── Issuer passthrough (RFC 9207 §4) ─────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocument_ReturnsIssuerExactlyAsConfigured()
    {
        const string issuer = "https://auth.example.com";

        var doc = await GetDocumentAsync(new AuthorizationServerOptions { Issuer = issuer });

        doc.Issuer.Should().Be(issuer);
    }

    // ── URI derivation — root issuer (no path) ────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocument_RootIssuer_DerivesAuthorizationEndpoint()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        doc.AuthorizationEndpoint.Should().Be("https://auth.example.com/connect/authorize");
    }

    [Fact]
    public async Task GetDocument_RootIssuer_DerivesTokenEndpoint()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        doc.TokenEndpoint.Should().Be("https://auth.example.com/connect/token");
    }

    [Fact]
    public async Task GetDocument_RootIssuer_DerivesJwksUri()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        doc.JwksUri.Should().Be("https://auth.example.com/connect/jwks");
    }

    // ── URI derivation — path-bearing issuer ─────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocument_PathBearingIssuer_DerivesAuthorizationEndpointUnderIssuerPath()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1",
        });

        doc.AuthorizationEndpoint.Should().Be("https://auth.example.com/tenant1/connect/authorize");
    }

    [Fact]
    public async Task GetDocument_PathBearingIssuer_DerivesTokenEndpointUnderIssuerPath()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1",
        });

        doc.TokenEndpoint.Should().Be("https://auth.example.com/tenant1/connect/token");
    }

    [Fact]
    public async Task GetDocument_PathBearingIssuer_DerivesJwksUriUnderIssuerPath()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1",
        });

        doc.JwksUri.Should().Be("https://auth.example.com/tenant1/connect/jwks");
    }

    // ── Explicit URI overrides ────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetDocument_ExplicitAuthorizationEndpoint_UsesOverrideNotDerivedValue()
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
    public async Task GetDocument_ExplicitTokenEndpoint_UsesOverrideNotDerivedValue()
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
    public async Task GetDocument_ExplicitJwksUri_UsesOverrideNotDerivedValue()
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
    public async Task GetDocument_DefaultOptions_IncludesDefaultCollectionValues()
    {
        var doc = await GetDocumentAsync(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        doc.ResponseTypesSupported.Should().ContainSingle().Which.Should().Be(ResponseType.Code);
        doc.ScopesSupported.Should().Equal(StandardScopes.OpenId.Name, StandardScopes.Profile.Name);
        doc.ResponseModesSupported.Should().ContainSingle().Which.Should().Be(ResponseMode.Query);
        doc.GrantTypesSupported.Should().ContainSingle().Which.Should().Be(GrantType.AuthorizationCode);
        doc.TokenEndpointAuthMethodsSupported.Should().ContainSingle().Which.Should().Be(TokenEndpointAuthMethod.ClientSecretBasic);
        doc.SubjectTypesSupported.Should().ContainSingle().Which.Should().Be("public");
        doc.IdTokenSigningAlgValuesSupported.Should().ContainSingle().Which.Should().Be(SigningAlgorithm.RS256);
    }

    [Fact]
    public async Task GetDocument_CustomCollections_UsesConfiguredValues()
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
            TokenEndpoint = { AuthMethodsSupported = [TokenEndpointAuthMethod.ClientSecretBasic, TokenEndpointAuthMethod.PrivateKeyJwt] },
            IdToken = { SigningAlgValuesSupported = [SigningAlgorithm.RS256, SigningAlgorithm.PS256] },
        }, scopeRepository);

        doc.ResponseTypesSupported.Should().Equal(ResponseType.Code);
        doc.ScopesSupported.Should().Equal(StandardScopes.OpenId.Name, StandardScopes.Profile.Name);
        doc.ResponseModesSupported.Should().Equal(ResponseMode.Query, ResponseMode.FormPost);
        doc.GrantTypesSupported.Should().Equal(GrantType.AuthorizationCode, GrantType.RefreshToken);
        doc.TokenEndpointAuthMethodsSupported.Should().Equal(
            TokenEndpointAuthMethod.ClientSecretBasic,
            TokenEndpointAuthMethod.PrivateKeyJwt);
        doc.IdTokenSigningAlgValuesSupported.Should().Equal(SigningAlgorithm.RS256, SigningAlgorithm.PS256);
    }

    [Fact]
    public async Task GetDocument_ScopeRepository_UsesRepositoryScopesForDiscovery()
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
    public async Task GetDocument_ScopeRepository_ExcludesNonDiscoverableScopes()
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
    public async Task GetDocumentAsync_AlreadyCancelledToken_ThrowsViaDefaultScopeRepository()
    {
        var options = Microsoft.Extensions.Options.Options.Create(
            new AuthorizationServerOptions { Issuer = "https://auth.example.com" });
        var provider = new DiscoveryDocumentProvider(options, new DefaultScopeRepository());

        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        var act = async () => await provider.GetDocumentAsync(cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task GetDocumentAsync_PropagatesTokenToScopeRepository()
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
    public async Task GetDocumentAsync_ScopeRepositoryCancels_ExceptionSurfaces()
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
}
