using System.Reflection;
using ZeeKayDa.Auth.Authorization;
using ZeeKayDa.Auth.Configuration;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Configuration;

public sealed class AuthorizationServerOptionsPostConfigurerTests
{
    private static AuthorizationServerOptions PostConfigure(AuthorizationServerOptions options)
    {
        new AuthorizationServerOptionsPostConfigurer().PostConfigure(null, options);
        return options;
    }

    // ── Every collection ─────────────────────────────────────────────────────────────────────────

    [Fact]
    public void PostConfigure_freezes_every_collection_on_the_options_graph()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        var collections = CollectionProperties(options).ToList();
        foreach (var collection in collections.Where(collection => collection.Value is null))
            collection.Assign(Activator.CreateInstance(typeof(List<>).MakeGenericType(collection.ElementType)));

        PostConfigure(options);

        CollectionProperties(options).Should().AllSatisfy(collection =>
        {
            collection.IsReadOnly().Should().BeTrue($"{collection.Path} must be frozen after post-configuration");
            collection.Invoking(c => c.AddDefault()).Should().Throw<TargetInvocationException>()
                .WithInnerException<NotSupportedException>($"{collection.Path} must reject Add after post-configuration");
        });
    }

    [Fact]
    public void CollectionProperties_reaches_every_collection_the_options_graph_declares_today()
    {
        // Proves the walker behind the freezing test descends into the option groups; a walker that
        // found nothing would let that test pass vacuously.
        var paths = CollectionProperties(new AuthorizationServerOptions()).Select(collection => collection.Path);

        paths.Should().BeEquivalentTo(
            "GrantTypesSupported",
            "CorsOrigins",
            "AuthorizationEndpoint.CodeChallengeMethodsSupported",
            "TokenEndpoint.AuthMethodsSupported",
            "IdToken.AdvertisedSigningAlgorithms",
            "Response.TypesSupported",
            "Response.ModesSupported");
    }

    [Fact]
    public void PostConfigure_makes_GrantTypesSupported_reject_Add()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };

        PostConfigure(options);

        var act = () => options.GrantTypesSupported.Add(GrantType.ClientCredentials);
        act.Should().Throw<NotSupportedException>();
    }

    [Fact]
    public void PostConfigure_keeps_the_host_values_order_and_duplicates_of_a_collection()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.TokenEndpoint.AuthMethodsSupported =
        [
            TokenEndpointAuthMethods.ClientSecretPost,
            TokenEndpointAuthMethods.None,
            TokenEndpointAuthMethods.ClientSecretPost,
        ];

        PostConfigure(options);

        options.TokenEndpoint.AuthMethodsSupported.Should().Equal(
            TokenEndpointAuthMethods.ClientSecretPost,
            TokenEndpointAuthMethods.None,
            TokenEndpointAuthMethods.ClientSecretPost);
    }

    [Fact]
    public void PostConfigure_copies_the_host_collection_so_the_host_instance_cannot_change_it()
    {
        var hostList = new List<GrantType> { GrantType.AuthorizationCode };
        var options = new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = hostList,
        };

        PostConfigure(options);
        hostList.Add(GrantType.ClientCredentials);

        options.GrantTypesSupported.Should().Equal(GrantType.AuthorizationCode);
    }

    [Fact]
    public void PostConfigure_leaves_a_null_CodeChallengeMethodsSupported_null()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.AuthorizationEndpoint.CodeChallengeMethodsSupported = null;

        PostConfigure(options);

        options.AuthorizationEndpoint.CodeChallengeMethodsSupported.Should().BeNull(
            "null means the field is omitted from the discovery document");
    }

    [Fact]
    public void PostConfigure_leaves_a_null_GrantTypesSupported_for_validation_to_report()
    {
        var options = new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            GrantTypesSupported = null!,
        };

        PostConfigure(options);
        var act = () => new AuthorizationServerOptionsValidator().Validate(null, options);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "configuration.grant_types_supported.null");
    }

    [Fact]
    public void Validate_accepts_the_frozen_default_options()
    {
        var options = PostConfigure(new AuthorizationServerOptions { Issuer = "https://auth.example.com" });

        var result = new AuthorizationServerOptionsValidator().Validate(null, options);

        result.Succeeded.Should().BeTrue();
    }

    // ── CorsOrigins ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void PostConfigure_keeps_CorsOrigins_exactly_as_the_host_configured_them()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.CorsOrigins.Add("HTTPS://APP.EXAMPLE.COM/");
        options.CorsOrigins.Add("https://app.example.com");
        options.CorsOrigins.Add("not-a-uri");

        PostConfigure(options);

        options.CorsOrigins.Should().Equal("HTTPS://APP.EXAMPLE.COM/", "https://app.example.com", "not-a-uri");
    }

    [Fact]
    public void PostConfigure_freezes_the_collection_as_read_only()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.CorsOrigins.Add("https://app.example.com");

        PostConfigure(options);

        options.CorsOrigins.IsReadOnly.Should().BeTrue();
        var act = () => options.CorsOrigins.Add("https://admin.example.com");
        act.Should().Throw<NotSupportedException>();
    }

    [Fact]
    public void PostConfigure_freezes_empty_collection()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };

        PostConfigure(options);

        options.CorsOrigins.IsReadOnly.Should().BeTrue();
    }

    [Fact]
    public void PostConfigure_is_idempotent_on_repeated_calls()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.CorsOrigins.Add("HTTPS://APP.EXAMPLE.COM");
        PostConfigure(options);
        PostConfigure(options);

        options.CorsOrigins.Should().Equal("HTTPS://APP.EXAMPLE.COM");
    }

    // ── IdToken.AdvertisedSigningAlgorithms ──────────────────────────────────────────────────────

    [Fact]
    public void PostConfigure_freezes_AdvertisedSigningAlgorithms()
    {
        // The discovery document reads this filter on every request; the startup checks that
        // reconcile it with the key set run exactly once.
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.IdToken.AdvertisedSigningAlgorithms = [SigningAlgorithm.RS256];

        new AuthorizationServerOptionsPostConfigurer().PostConfigure(name: null, options);

        options.IdToken.AdvertisedSigningAlgorithms!.IsReadOnly.Should().BeTrue();
    }

    [Fact]
    public void PostConfigure_preserves_the_AdvertisedSigningAlgorithms_entries()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };
        options.IdToken.AdvertisedSigningAlgorithms = [SigningAlgorithm.RS256, SigningAlgorithm.ES256];

        new AuthorizationServerOptionsPostConfigurer().PostConfigure(name: null, options);

        options.IdToken.AdvertisedSigningAlgorithms.Should().Equal(
            SigningAlgorithm.RS256, SigningAlgorithm.ES256);
    }

    [Fact]
    public void PostConfigure_leaves_a_null_AdvertisedSigningAlgorithms_null()
    {
        var options = new AuthorizationServerOptions { Issuer = "https://auth.example.com" };

        new AuthorizationServerOptionsPostConfigurer().PostConfigure(name: null, options);

        options.IdToken.AdvertisedSigningAlgorithms.Should().BeNull(
            "null is the default and means advertise the whole published key set");
    }

    /// <summary>
    /// Every property of a generic collection type on the options and, recursively, on each option
    /// group the framework declares, named by its path from the root.
    /// </summary>
    private static IEnumerable<CollectionProperty> CollectionProperties(object owner, string prefix = "") =>
        owner.GetType()
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .SelectMany(property => CollectionProperties(owner, property, prefix + property.Name));

    private static IEnumerable<CollectionProperty> CollectionProperties(object owner, PropertyInfo property, string path)
    {
        if (CollectionElementType(property.PropertyType) is { } elementType)
            return [new CollectionProperty(owner, property, path, elementType)];

        return IsOptionGroup(property.PropertyType) && property.GetValue(owner) is { } group
            ? CollectionProperties(group, path + ".")
            : [];
    }

    private static bool IsOptionGroup(Type type) =>
        type.IsClass && type != typeof(string) && type.Assembly == typeof(AuthorizationServerOptions).Assembly;

    private static Type? CollectionElementType(Type type) =>
        IsGenericCollection(type) ? type.GetGenericArguments()[0] : null;

    private static bool IsGenericCollection(Type type) =>
        type != typeof(string) && type.IsGenericType && typeof(System.Collections.IEnumerable).IsAssignableFrom(type);

    private sealed record CollectionProperty(object Owner, PropertyInfo Property, string Path, Type ElementType)
    {
        public void Assign(object? value) => Property.SetValue(Owner, value);

        public bool IsReadOnly() => (bool)CollectionInterface.GetProperty("IsReadOnly")!.GetValue(Value)!;

        public void AddDefault() => CollectionInterface.GetMethod("Add")!.Invoke(Value, [DefaultElement]);

        public object? Value => Property.GetValue(Owner);

        private Type CollectionInterface => typeof(ICollection<>).MakeGenericType(ElementType);

        private object? DefaultElement => ElementType.IsValueType ? Activator.CreateInstance(ElementType) : null;
    }
}
