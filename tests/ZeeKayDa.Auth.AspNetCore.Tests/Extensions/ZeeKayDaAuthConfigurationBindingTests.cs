using System.Reflection;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Extensions;

public sealed class ZeeKayDaAuthConfigurationBindingTests
{
    [Fact]
    public void AddZeeKayDaAuth_binds_every_kind_of_option_from_a_configuration_section()
    {
        var options = Resolve(new Dictionary<string, string?>
        {
            ["Issuer"] = "https://auth.example.com",
            ["ClockSkewTolerance"] = "00:00:10",
            ["GrantTypesSupported:0"] = "AuthorizationCode",
            ["GrantTypesSupported:1"] = "RefreshToken",
            ["CorsOrigins:0"] = "https://app.example.com",
            ["TokenEndpoint:AccessTokenLifetime"] = "00:20:00",
            ["TokenEndpoint:AdvertisedAuthMethods:0"] = "client_secret_post",
            ["AuthorizationEndpoint:MaxRequestContextBytes"] = "2048",
            ["AuthorizationEndpoint:CodeChallengeMethodsSupported:0"] = "S256",
            ["AuthorizationEndpoint:Interaction:LoginPath"] = "/sign-in",
            ["AuthorizationEndpoint:Interaction:SupportsLocalSignIn"] = "false",
            ["Response:TypesSupported:0"] = "Code",
            ["Response:ModesSupported:0"] = "Query",
            ["IdToken:AdvertisedSigningAlgorithms:0"] = "ES256",
            ["Development:AllowHttpLoopbackIssuer"] = "true",
        });

        options.Issuer.Should().Be("https://auth.example.com");
        options.ClockSkewTolerance.Should().Be(TimeSpan.FromSeconds(10));
        options.GrantTypesSupported.Should().Equal(GrantType.AuthorizationCode, GrantType.RefreshToken);
        options.CorsOrigins.Should().Equal("https://app.example.com");
        options.TokenEndpoint.AccessTokenLifetime.Should().Be(TimeSpan.FromMinutes(20));
        options.TokenEndpoint.AdvertisedAuthMethods.Should().Equal("client_secret_post");
        options.AuthorizationEndpoint.MaxRequestContextBytes.Should().Be(2048);
        options.AuthorizationEndpoint.CodeChallengeMethodsSupported.Should().Equal(CodeChallengeMethod.S256);
        options.AuthorizationEndpoint.Interaction.LoginPath.Should().Be("/sign-in");
        options.AuthorizationEndpoint.Interaction.SupportsLocalSignIn.Should().BeFalse();
        options.Response.TypesSupported.Should().Equal(ResponseType.Code);
        options.Response.ModesSupported.Should().Equal(ResponseMode.Query);
        options.IdToken.AdvertisedSigningAlgorithms.Should().Equal(SigningAlgorithm.ES256);
        options.Development.AllowHttpLoopbackIssuer.Should().BeTrue();
    }

    [Fact]
    public void A_configured_collection_replaces_its_default_instead_of_appending()
    {
        var options = Resolve(new Dictionary<string, string?>
        {
            ["Issuer"] = "https://auth.example.com",
            ["GrantTypesSupported:0"] = "ClientCredentials",
            ["TokenEndpoint:AdvertisedAuthMethods:0"] = "client_secret_post",
            ["Response:TypesSupported:0"] = "Code",
            ["Response:ModesSupported:0"] = "Query",
            ["AuthorizationEndpoint:CodeChallengeMethodsSupported:0"] = "S256",
        });

        options.GrantTypesSupported.Should().Equal(GrantType.ClientCredentials);
        options.TokenEndpoint.AdvertisedAuthMethods.Should().Equal("client_secret_post");
        options.Response.TypesSupported.Should().Equal(ResponseType.Code);
        options.Response.ModesSupported.Should().Equal(ResponseMode.Query);
        options.AuthorizationEndpoint.CodeChallengeMethodsSupported.Should().Equal(CodeChallengeMethod.S256);
    }

    [Fact]
    public void An_empty_JSON_array_replaces_the_default_with_an_empty_collection()
    {
        // The JSON provider records [] as a key with an empty value, so the key exists and replaces;
        // the in-memory provider used elsewhere here cannot express an empty array at all.
        var section = new ConfigurationBuilder()
            .AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes("""{ "GrantTypesSupported": [] }""")))
            .Build();
        var options = new AuthorizationServerOptions();

        AuthorizationServerOptionsBinder.Bind(section, options);

        options.GrantTypesSupported.Should().BeEmpty();
    }

    [Fact]
    public void A_collection_missing_from_configuration_keeps_its_default()
    {
        var options = Resolve(new Dictionary<string, string?> { ["Issuer"] = "https://auth.example.com" });

        options.GrantTypesSupported.Should().Equal(GrantType.AuthorizationCode);
        options.TokenEndpoint.AdvertisedAuthMethods.Should().BeNull();
        options.IdToken.AdvertisedSigningAlgorithms.Should().BeNull();
    }

    [Fact]
    public void The_configure_delegate_runs_after_binding_and_sees_the_bound_values()
    {
        var options = Resolve(
            new Dictionary<string, string?>
            {
                ["Issuer"] = "https://auth.example.com",
                ["TokenEndpoint:AdvertisedAuthMethods:0"] = "client_secret_post",
            },
            configure => configure.TokenEndpoint.AdvertisedAuthMethods!.Add(TokenEndpointAuthMethods.None));

        options.TokenEndpoint.AdvertisedAuthMethods.Should().Equal("client_secret_post", "none");
    }

    [Fact]
    public void The_issuer_overload_sets_the_issuer_before_the_configure_delegate_runs()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        string? seen = null;
        services.AddZeeKayDaAuth("https://auth.example.com", options => seen = options.Issuer);
        using var provider = services.BuildServiceProvider();

        var options = provider.GetRequiredService<IOptions<AuthorizationServerOptions>>().Value;

        (options.Issuer, seen).Should().Be(("https://auth.example.com", "https://auth.example.com"));
    }

    public static TheoryData<string> SettableCollectionOptions() =>
        [.. SettableCollectionPaths(typeof(AuthorizationServerOptions), prefix: "")];

    [Theory]
    [MemberData(nameof(SettableCollectionOptions))]
    public void Every_settable_collection_option_is_replaced_by_configuration_not_appended_to(string path)
    {
        // Seeds the collection with one value, then configures another: an appending binder keeps both.
        var options = new AuthorizationServerOptions();
        var (owner, property) = Locate(options, path);
        var elementType = property.PropertyType.GetGenericArguments()[0];
        var (seed, configured) = TwoDistinctValues(elementType);
        var collection = Activator.CreateInstance(typeof(List<>).MakeGenericType(elementType))!;
        ((System.Collections.IList)collection).Add(seed);
        property.SetValue(owner, collection);

        var section = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { [path + ":0"] = configured.ToString() })
            .Build();
        AuthorizationServerOptionsBinder.Bind(section, options);

        ((System.Collections.IEnumerable)property.GetValue(owner)!).Cast<object>().Should().Equal(configured);
    }

    private static AuthorizationServerOptions Resolve(
        Dictionary<string, string?> values,
        Action<AuthorizationServerOptions>? configure = null)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddZeeKayDaAuth(configuration, configure);
        using var provider = services.BuildServiceProvider();
        return provider.GetRequiredService<IOptions<AuthorizationServerOptions>>().Value;
    }

    private static (object Owner, PropertyInfo Property) Locate(object options, string path)
    {
        var names = path.Split(':');
        var owner = options;
        foreach (var name in names[..^1])
            owner = owner.GetType().GetProperty(name)!.GetValue(owner)!;

        return (owner, owner.GetType().GetProperty(names[^1])!);
    }

    private static (object Seed, object Configured) TwoDistinctValues(Type elementType)
    {
        if (elementType == typeof(string))
            return ("seeded", "configured");

        var values = Enum.GetValues(elementType);
        return (values.GetValue(0)!, values.GetValue(values.Length - 1)!);
    }

    private static IEnumerable<string> SettableCollectionPaths(Type type, string prefix) =>
        type.GetProperties(BindingFlags.Public | BindingFlags.Instance).SelectMany(property =>
        {
            var path = prefix + property.Name;
            if (IsCollection(property.PropertyType))
                return property.CanWrite ? [path] : [];

            return property.PropertyType.Namespace?.StartsWith("ZeeKayDa.Auth", StringComparison.Ordinal) == true
                && property.PropertyType.IsClass
                ? SettableCollectionPaths(property.PropertyType, path + ":")
                : [];
        });

    private static bool IsCollection(Type type) =>
        type.IsGenericType && type.GetGenericTypeDefinition() == typeof(ICollection<>);
}
