using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Discovery;
using ZeeKayDa.Auth.Scopes;

namespace ZeeKayDa.Auth.Tests.Discovery;

public sealed class DiscoveryDocumentProviderTests
{
    private static OpenIdConfigurationDocument GetDocument(
        AuthorizationServerOptions options,
        IScopeRepository? scopeRepository = null)
    {
        var optionsWrapper = Microsoft.Extensions.Options.Options.Create(options);
        var provider = new DiscoveryDocumentProvider(
            optionsWrapper,
            scopeRepository ?? new DefaultScopeRepository());
        return provider.GetDocument();
    }

    // ── Issuer passthrough (RFC 9207 §4) ─────────────────────────────────────────────────────────

    [Fact]
    public void GetDocument_ReturnsIssuerExactlyAsConfigured()
    {
        const string issuer = "https://auth.example.com";

        var doc = GetDocument(new AuthorizationServerOptions { Issuer = issuer });

        doc.Issuer.Should().Be(issuer);
    }

    // ── URI derivation — root issuer (no path) ────────────────────────────────────────────────────

    [Fact]
    public void GetDocument_RootIssuer_DerivesAuthorizationEndpoint()
    {
        var doc = GetDocument(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        doc.AuthorizationEndpoint.Should().Be("https://auth.example.com/connect/authorize");
    }

    [Fact]
    public void GetDocument_RootIssuer_DerivesTokenEndpoint()
    {
        var doc = GetDocument(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        doc.TokenEndpoint.Should().Be("https://auth.example.com/connect/token");
    }

    [Fact]
    public void GetDocument_RootIssuer_DerivesJwksUri()
    {
        var doc = GetDocument(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        doc.JwksUri.Should().Be("https://auth.example.com/connect/jwks");
    }

    // ── URI derivation — path-bearing issuer ─────────────────────────────────────────────────────

    [Fact]
    public void GetDocument_PathBearingIssuer_DerivesAuthorizationEndpointUnderIssuerPath()
    {
        var doc = GetDocument(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1",
        });

        doc.AuthorizationEndpoint.Should().Be("https://auth.example.com/tenant1/connect/authorize");
    }

    [Fact]
    public void GetDocument_PathBearingIssuer_DerivesTokenEndpointUnderIssuerPath()
    {
        var doc = GetDocument(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1",
        });

        doc.TokenEndpoint.Should().Be("https://auth.example.com/tenant1/connect/token");
    }

    [Fact]
    public void GetDocument_PathBearingIssuer_DerivesJwksUriUnderIssuerPath()
    {
        var doc = GetDocument(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1",
        });

        doc.JwksUri.Should().Be("https://auth.example.com/tenant1/connect/jwks");
    }

    // ── URI derivation — trailing-slash issuer ────────────────────────────────────────────────────

    [Fact]
    public void GetDocument_TrailingSlashIssuer_DerivesEndpointsWithoutDoubleSlash()
    {
        var doc = GetDocument(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com/tenant1/",
        });

        doc.AuthorizationEndpoint.Should().Be("https://auth.example.com/tenant1/connect/authorize");
        doc.TokenEndpoint.Should().Be("https://auth.example.com/tenant1/connect/token");
        doc.JwksUri.Should().Be("https://auth.example.com/tenant1/connect/jwks");
    }

    // ── Explicit URI overrides ────────────────────────────────────────────────────────────────────

    [Fact]
    public void GetDocument_ExplicitAuthorizationEndpoint_UsesOverrideNotDerivedValue()
    {
        const string explicitUri = "https://other.example.com/custom/authorize";

        var doc = GetDocument(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            AuthorizationEndpoint = explicitUri,
        });

        doc.AuthorizationEndpoint.Should().Be(explicitUri);
    }

    [Fact]
    public void GetDocument_ExplicitTokenEndpoint_UsesOverrideNotDerivedValue()
    {
        const string explicitUri = "https://other.example.com/custom/token";

        var doc = GetDocument(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            TokenEndpoint = explicitUri,
        });

        doc.TokenEndpoint.Should().Be(explicitUri);
    }

    [Fact]
    public void GetDocument_ExplicitJwksUri_UsesOverrideNotDerivedValue()
    {
        const string explicitUri = "https://other.example.com/custom/jwks";

        var doc = GetDocument(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            JwksUri = explicitUri,
        });

        doc.JwksUri.Should().Be(explicitUri);
    }

    // ── Collection fields ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void GetDocument_DefaultOptions_IncludesDefaultCollectionValues()
    {
        var doc = GetDocument(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
        });

        doc.ResponseTypesSupported.Should().ContainSingle().Which.Should().Be(ResponseType.Code);
        doc.ScopesSupported.Should().Equal(ScopeNames.OpenId, ScopeNames.Profile);
        doc.ResponseModesSupported.Should().ContainSingle().Which.Should().Be(ResponseMode.Query);
        doc.GrantTypesSupported.Should().ContainSingle().Which.Should().Be(GrantType.AuthorizationCode);
        doc.TokenEndpointAuthMethodsSupported.Should().ContainSingle().Which.Should().Be(TokenEndpointAuthMethod.ClientSecretBasic);
        doc.SubjectTypesSupported.Should().ContainSingle().Which.Should().Be("public");
        doc.IdTokenSigningAlgValuesSupported.Should().ContainSingle().Which.Should().Be(SigningAlgorithm.RS256);
    }

    [Fact]
    public void GetDocument_CustomCollections_UsesConfiguredValues()
    {
        var scopeRepository = new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = ScopeNames.OpenId },
            new ScopeDefinition { Name = ScopeNames.Profile },
        ]);

        var doc = GetDocument(new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            ResponseTypesSupported = [ResponseType.Code, ResponseType.CodeIdToken],
            ResponseModesSupported = [ResponseMode.Query, ResponseMode.FormPost],
            GrantTypesSupported = [GrantType.AuthorizationCode, GrantType.RefreshToken],
            TokenEndpointAuthMethodsSupported = [TokenEndpointAuthMethod.ClientSecretBasic, TokenEndpointAuthMethod.PrivateKeyJwt],
            IdTokenSigningAlgValuesSupported = [SigningAlgorithm.RS256, SigningAlgorithm.PS256],
        }, scopeRepository);

        doc.ResponseTypesSupported.Should().Equal(ResponseType.Code, ResponseType.CodeIdToken);
        doc.ScopesSupported.Should().Equal(ScopeNames.OpenId, ScopeNames.Profile);
        doc.ResponseModesSupported.Should().Equal(ResponseMode.Query, ResponseMode.FormPost);
        doc.GrantTypesSupported.Should().Equal(GrantType.AuthorizationCode, GrantType.RefreshToken);
        doc.TokenEndpointAuthMethodsSupported.Should().Equal(
            TokenEndpointAuthMethod.ClientSecretBasic,
            TokenEndpointAuthMethod.PrivateKeyJwt);
        doc.IdTokenSigningAlgValuesSupported.Should().Equal(SigningAlgorithm.RS256, SigningAlgorithm.PS256);
    }

    [Fact]
    public void GetDocument_ScopeRepository_UsesRepositoryScopesForDiscovery()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition
            {
                Name = ScopeNames.OpenId,
                IdTokenClaims = ["sub"],
                AccessTokenClaims = ["scope"],
            },
            new ScopeDefinition
            {
                Name = ScopeNames.Profile,
                IdTokenClaims = ["name", "family_name"],
                AccessTokenClaims = ["name"],
            },
        ]);

        var doc = GetDocument(
            new AuthorizationServerOptions
            {
                Issuer = "https://auth.example.com",
            },
            repository);

        doc.ScopesSupported.Should().Equal(ScopeNames.OpenId, ScopeNames.Profile);
    }

    [Fact]
    public void GetDocument_ScopeRepository_ExcludesNonDiscoverableScopes()
    {
        var repository = new InMemoryScopeRepository(
        [
            new ScopeDefinition { Name = ScopeNames.OpenId },
            new ScopeDefinition
            {
                Name = "internal.admin",
                IsDiscoverable = false,
                AccessTokenClaims = ["scope"],
            },
        ]);

        var doc = GetDocument(
            new AuthorizationServerOptions
            {
                Issuer = "https://auth.example.com",
            },
            repository);

        doc.ScopesSupported.Should().Equal(ScopeNames.OpenId);
    }
}
