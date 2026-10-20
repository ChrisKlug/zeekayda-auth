using System.Net;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.StartupVerification;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

/// <summary>
/// The host's rate limiter is the control on the framework's endpoints: <c>MapZeeKayDaAuth()</c>
/// returns the builder a host attaches it to, and startup warns outside Development when an
/// endpoint is reached by no limiter.
/// </summary>
public sealed class EndpointRateLimitingActivatorTests
{
    private const string Policy = "auth";

    private const string DiscoveryPath = "/.well-known/openid-configuration";

    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    private sealed class ProductionEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = "/";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    [Fact]
    public async Task A_host_attaching_no_rate_limiter_starts_with_a_warning()
    {
        var logs = await StartAsync(Environments.Production);

        logs.Should().ContainSingle(entry => entry.Message.Contains(EndpointRateLimitingActivator.NotRateLimitedCode, StringComparison.Ordinal))
            .Which.Level.Should().Be(LogLevel.Warning);
    }

    [Fact]
    public async Task A_policy_attached_through_MapZeeKayDaAuth_starts_without_the_warning()
    {
        var logs = await StartAsync(
            Environments.Production,
            limiter => limiter.AddFixedWindowLimiter(Policy, PermitPerMinute),
            frameworkEndpoints => frameworkEndpoints.RequireRateLimiting(Policy));

        logs.Should().NotContain(entry => entry.Message.Contains(EndpointRateLimitingActivator.NotRateLimitedCode, StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_global_limiter_starts_without_the_warning()
    {
        var logs = await StartAsync(
            Environments.Production,
            limiter => limiter.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(_ => RateLimitPartition.GetNoLimiter("all")));

        logs.Should().NotContain(entry => entry.Message.Contains(EndpointRateLimitingActivator.NotRateLimitedCode, StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_host_in_Development_starts_without_the_warning()
    {
        var logs = await StartAsync(Environments.Development);

        logs.Should().NotContain(entry => entry.Message.Contains(EndpointRateLimitingActivator.NotRateLimitedCode, StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_host_limiting_upstream_silences_the_warning_with_a_log_filter_on_the_check_category()
    {
        var logs = await StartAsync(
            Environments.Production,
            configureLogging: logging => logging.AddFilter("ZeeKayDa.Auth.AspNetCore.Endpoints.EndpointRateLimitingActivator", LogLevel.Error));

        logs.Should().NotContain(entry => entry.Message.Contains(EndpointRateLimitingActivator.NotRateLimitedCode, StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_policy_attached_through_MapZeeKayDaAuth_limits_the_framework_endpoints()
    {
        await using var app = await StartAppAsync(
            limiter => limiter.AddFixedWindowLimiter(Policy, PermitPerMinute),
            frameworkEndpoints => frameworkEndpoints.RequireRateLimiting(Policy));
        using var client = HttpsClient(app);

        await client.GetAsync(DiscoveryPath, Cancellation);
        var response = await client.GetAsync(DiscoveryPath, Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
    }

    [Fact]
    public async Task A_policy_attached_through_MapZeeKayDaAuth_leaves_the_host_routes_unlimited()
    {
        await using var app = await StartAppAsync(
            limiter => limiter.AddFixedWindowLimiter(Policy, PermitPerMinute),
            frameworkEndpoints => frameworkEndpoints.RequireRateLimiting(Policy),
            hostEndpoints => hostEndpoints.MapGet("/ping", () => "pong"));
        using var client = HttpsClient(app);

        await client.GetAsync("/ping", Cancellation);
        var response = await client.GetAsync("/ping", Cancellation);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task An_endpoint_opted_out_is_warned_about_though_a_global_limiter_is_set()
    {
        var context = await VerifyAsync(globalLimiter: true, EndpointWith(new DisableRateLimitingAttribute()));

        context.Warnings.Should().ContainSingle().Which.Code.Should().Be(EndpointRateLimitingActivator.NotRateLimitedCode);
    }

    [Fact]
    public async Task An_opt_out_wins_over_a_policy_on_the_same_endpoint()
    {
        var context = await VerifyAsync(
            globalLimiter: false,
            EndpointWith(new EnableRateLimitingAttribute(Policy), new DisableRateLimitingAttribute()));

        context.Warnings.Should().ContainSingle().Which.Code.Should().Be(EndpointRateLimitingActivator.NotRateLimitedCode);
    }

    [Fact]
    public async Task One_unlimited_endpoint_among_limited_ones_is_warned_about()
    {
        var context = await VerifyAsync(
            globalLimiter: false,
            EndpointWith(new EnableRateLimitingAttribute(Policy)),
            EndpointWith());

        context.Warnings.Should().ContainSingle().Which.Code.Should().Be(EndpointRateLimitingActivator.NotRateLimitedCode);
    }

    private static void PermitPerMinute(FixedWindowRateLimiterOptions window)
    {
        window.PermitLimit = 1;
        window.Window = TimeSpan.FromMinutes(1);
    }

    private static Endpoint EndpointWith(params object[] metadata) =>
        new(requestDelegate: null, new EndpointMetadataCollection(metadata), "framework endpoint");

    private static async Task<StartupVerificationContext> VerifyAsync(bool globalLimiter, params Endpoint[] endpoints)
    {
        var mapped = new MappedFrameworkEndpoints();
        mapped.Add(new DefaultEndpointDataSource(endpoints));
        using var limiter = globalLimiter
            ? PartitionedRateLimiter.Create<HttpContext, string>(_ => RateLimitPartition.GetNoLimiter("all"))
            : null;
        var activator = new EndpointRateLimitingActivator(
            mapped,
            Options.Create(new RateLimiterOptions { GlobalLimiter = limiter }),
            new ProductionEnvironment());
        var context = new StartupVerificationContext();

        await activator.VerifyAsync(context, Cancellation);

        return context;
    }

    private static async Task<IReadOnlyList<(string Category, LogLevel Level, string Message)>> StartAsync(
        string environment,
        Action<RateLimiterOptions>? configureLimiter = null,
        Action<IEndpointConventionBuilder>? conventions = null,
        Action<ILoggingBuilder>? configureLogging = null)
    {
        var logs = new CapturingLoggerProvider();

        await using (await StartAppAsync(configureLimiter, conventions, environment: environment, configureLogging: logging =>
        {
            logging.AddProvider(logs);
            configureLogging?.Invoke(logging);
        }))
        {
            return logs.Entries;
        }
    }

    private static async Task<WebApplication> StartAppAsync(
        Action<RateLimiterOptions>? configureLimiter = null,
        Action<IEndpointConventionBuilder>? conventions = null,
        Action<IEndpointRouteBuilder>? hostEndpoints = null,
        string environment = "Production",
        Action<ILoggingBuilder>? configureLogging = null)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = environment });
        builder.WebHost.UseTestServer();
        configureLogging?.Invoke(builder.Logging);
        builder.Services.AddZeeKayDaAuth(options =>
            {
                options.Issuer = "https://test.example.com";
                options.AuthorizationEndpoint.Interaction.LoginPath = "/account/login";
                options.AuthorizationEndpoint.Interaction.ConsentPath = "/account/consent";
            })
            .AddInMemoryClients(clients => clients.AddDefaultTestClient(configureOptions: null))
            .AddInMemoryStores(allowOutsideDevelopment: true)
            .AddTestSigningKeys()
            .AddTestClaimsProvider();
        if (configureLimiter is not null)
            builder.Services.AddRateLimiter(configureLimiter);

        var app = builder.Build();
        if (configureLimiter is not null)
            app.UseRateLimiter();
        var frameworkEndpoints = app.MapZeeKayDaAuth();
        conventions?.Invoke(frameworkEndpoints);
        hostEndpoints?.Invoke(app);

        await app.StartAsync(Cancellation);
        return app;
    }

    private static HttpClient HttpsClient(WebApplication app)
    {
        var client = app.GetTestClient();
        client.BaseAddress = new Uri("https://test.example.com");
        return client;
    }
}
