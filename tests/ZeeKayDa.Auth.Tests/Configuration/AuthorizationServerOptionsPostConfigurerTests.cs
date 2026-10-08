using System.Reflection;
using Microsoft.Extensions.Options;
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

    // ── Defaults that depend on other settings ───────────────────────────────────────────────────

    [Fact]
    public void PostConfigure_defaults_RetainRetiredKeysFor_to_two_days_when_tokens_live_shorter()
    {
        PostConfigure(new AuthorizationServerOptions()).SigningKeys.RetainRetiredKeysFor
            .Should().Be(TimeSpan.FromDays(2));
    }

    [Theory]
    [InlineData(4, 3, 4)]
    [InlineData(3, 5, 5)]
    public void PostConfigure_defaults_RetainRetiredKeysFor_to_the_longer_token_lifetime_plus_the_clock_skew_tolerance(
        int accessTokenDays, int idTokenDays, int expectedDays)
    {
        var options = new AuthorizationServerOptions
        {
            ClockSkewTolerance = TimeSpan.FromSeconds(7),
            TokenEndpoint =
            {
                AccessTokenLifetime = TimeSpan.FromDays(accessTokenDays),
                IdTokenLifetime = TimeSpan.FromDays(idTokenDays),
            },
        };

        PostConfigure(options).SigningKeys.RetainRetiredKeysFor
            .Should().Be(TimeSpan.FromDays(expectedDays) + TimeSpan.FromSeconds(7));
    }

    [Fact]
    public void PostConfigure_saturates_the_default_RetainRetiredKeysFor_for_an_unbounded_token_lifetime()
    {
        var options = new AuthorizationServerOptions { TokenEndpoint = { AccessTokenLifetime = TimeSpan.MaxValue } };

        PostConfigure(options).SigningKeys.RetainRetiredKeysFor.Should().Be(TimeSpan.MaxValue);
    }

    [Fact]
    public void PostConfigure_with_a_negative_ClockSkewTolerance_leaves_the_failure_to_validation()
    {
        var options = new AuthorizationServerOptions { ClockSkewTolerance = TimeSpan.FromSeconds(-1) };

        var act = () => PostConfigure(options);

        act.Should().NotThrow();
    }

    [Fact]
    public void PostConfigure_with_negative_lifetimes_and_skew_beyond_TimeSpan_MinValue_leaves_the_failures_to_validation()
    {
        var options = new AuthorizationServerOptions
        {
            ClockSkewTolerance = TimeSpan.MinValue,
            TokenEndpoint = { AccessTokenLifetime = TimeSpan.FromDays(-1), IdTokenLifetime = TimeSpan.FromDays(-1) },
        };

        var act = () => PostConfigure(options);

        act.Should().NotThrow();
    }

    [Fact]
    public void PostConfigure_keeps_an_explicit_RetainRetiredKeysFor()
    {
        var options = new AuthorizationServerOptions { SigningKeys = { RetainRetiredKeysFor = TimeSpan.FromDays(3) } };

        PostConfigure(options).SigningKeys.RetainRetiredKeysFor.Should().Be(TimeSpan.FromDays(3));
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
            "TokenEndpoint.AdvertisedAuthMethods",
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
        options.TokenEndpoint.AdvertisedAuthMethods =
        [
            TokenEndpointAuthMethods.ClientSecretPost,
            TokenEndpointAuthMethods.None,
            TokenEndpointAuthMethods.ClientSecretPost,
        ];

        PostConfigure(options);

        options.TokenEndpoint.AdvertisedAuthMethods.Should().Equal(
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
        var act = () => ((IValidateOptions<AuthorizationServerOptions>)new AuthorizationServerOptionsValidator()).Validate(null, options);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "configuration.grant_types_supported.null");
    }

    [Fact]
    public void PostConfigure_leaves_a_null_CorsOrigins_for_validation_to_report()
    {
        var options = new AuthorizationServerOptions
        {
            Issuer = "https://auth.example.com",
            CorsOrigins = null!,
        };

        PostConfigure(options);
        var act = () => ((IValidateOptions<AuthorizationServerOptions>)new AuthorizationServerOptionsValidator()).Validate(null, options);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().Contain(f => f.Code == "configuration.cors_origins.null");
    }

    [Fact]
    public void Validate_accepts_the_frozen_default_options()
    {
        var options = PostConfigure(new AuthorizationServerOptions { Issuer = "https://auth.example.com" });

        var result = ((IValidateOptions<AuthorizationServerOptions>)new AuthorizationServerOptionsValidator()).Validate(null, options);

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
    public void Replacing_any_collection_after_PostConfigure_fails_with_options_frozen()
    {
        var options = PostConfigure(new AuthorizationServerOptions { Issuer = "https://auth.example.com" });

        CollectionProperties(options).Should().AllSatisfy(collection =>
        {
            var replacement = Activator.CreateInstance(typeof(List<>).MakeGenericType(collection.ElementType));
            var act = () => collection.Assign(replacement);

            act.Should().Throw<TargetInvocationException>(collection.Path)
                .WithInnerException<ZeeKayDaConfigurationException>()
                .Which.AggregatedFailures.Should().ContainSingle(f =>
                    f.Code == "configuration.options_frozen" && f.Message.Contains(collection.Path, StringComparison.Ordinal));
        });
    }

    // ── Development switches ─────────────────────────────────────────────────────────────────────

    [Fact]
    public void Flipping_any_Development_switch_after_PostConfigure_fails_with_options_frozen()
    {
        // A switch flipped at runtime would weaken security after its startup verifier reported
        // it off. Reflection, so a switch added later is covered without editing this test.
        var options = PostConfigure(new AuthorizationServerOptions { Issuer = "https://auth.example.com" });
        var switches = typeof(DevelopmentOptions).GetProperties().Where(p => p.PropertyType == typeof(bool)).ToList();

        switches.Should().HaveCount(3);
        switches.Should().AllSatisfy(property =>
        {
            var act = () => property.SetValue(options.Development, true);

            act.Should().Throw<TargetInvocationException>(property.Name)
                .WithInnerException<ZeeKayDaConfigurationException>()
                .Which.AggregatedFailures.Should().ContainSingle(f =>
                    f.Code == "configuration.options_frozen" &&
                    f.Message.Contains($"AuthorizationServerOptions.Development.{property.Name}", StringComparison.Ordinal));
            property.GetValue(options.Development).Should().Be(false, property.Name);
        });
    }

    [Fact]
    public void PostConfigure_keeps_the_Development_switches_the_host_configured()
    {
        var options = new AuthorizationServerOptions
        {
            Issuer = "http://localhost:5000",
            Development = { AllowHttpLoopbackIssuer = true, DisableExceptionSanitizing = true },
        };

        PostConfigure(options);

        options.Development.AllowHttpLoopbackIssuer.Should().BeTrue();
        options.Development.AllowHttpLoopbackCorsOrigins.Should().BeFalse();
        options.Development.DisableExceptionSanitizing.Should().BeTrue();
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
