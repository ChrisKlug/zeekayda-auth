using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore.Extensions;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// A <see cref="WebApplicationFactory{TEntryPoint}"/> that stands up a minimal ASP.NET Core host
/// with ZeeKayDa.Auth services registered, for use in integration tests.
/// </summary>
internal sealed class TestWebAppFactory : WebApplicationFactory<TestWebAppFactory>
{
    private readonly Action<AuthorizationServerOptions>? _configureOptions;
    private readonly Action<ZeeKayDaAuthBuilder>? _configureBuilder;

    /// <summary>
    /// Initialises a new factory instance.
    /// </summary>
    /// <param name="configureOptions">
    /// Optional delegate applied on top of the default options (issuer =
    /// <c>https://test.example.com</c>). Use this to override individual properties per test.
    /// </param>
    /// <param name="configureBuilder">
    /// Optional delegate used to register additional ZeeKayDa.Auth components, such as an
    /// in-memory scope repository, after <c>AddZeeKayDaAuth()</c> has been called.
    /// </param>
    public TestWebAppFactory(
        Action<AuthorizationServerOptions>? configureOptions = null,
        Action<ZeeKayDaAuthBuilder>? configureBuilder = null)
    {
        _configureOptions = configureOptions;
        _configureBuilder = configureBuilder;
    }

    /// <inheritdoc/>
    /// <remarks>
    /// Returns a <see cref="IHostBuilder"/> built from scratch rather than using the default
    /// TEntryPoint-based discovery, because the test project has no application entry point.
    /// All configuration is supplied by <see cref="ConfigureWebHost"/>.
    /// </remarks>
    protected override IHostBuilder CreateHostBuilder()
        => Host.CreateDefaultBuilder()
               .ConfigureWebHostDefaults(webBuilder => webBuilder.UseTestServer());

    /// <inheritdoc/>
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // Use the test output directory as content root since there is no application project.
        builder.UseContentRoot(AppContext.BaseDirectory);

        builder.ConfigureServices(services =>
        {
            services.AddRouting();

            var authBuilder = services.AddZeeKayDaAuth(options =>
            {
                // Default issuer used by most tests.
                options.Issuer = "https://test.example.com";

                // Allow per-test overrides (e.g. path-bearing issuer, AllowInsecureIssuer, etc.)
                _configureOptions?.Invoke(options);
            });

            _configureBuilder?.Invoke(authBuilder);
        });

        builder.Configure(app =>
        {
            app.UseRouting();
            app.UseEndpoints(endpoints => endpoints.MapZeeKayDaAuth());
        });
    }
}

/// <summary>
/// A <see cref="WebApplicationFactory{TEntryPoint}"/> that adds a <c>/ping</c> route outside
/// the ZeeKayDa.Auth endpoint group, for testing route-group isolation.
/// </summary>
internal sealed class TestWebAppFactoryWithPing : WebApplicationFactory<TestWebAppFactory>
{
    protected override IHostBuilder CreateHostBuilder()
        => Host.CreateDefaultBuilder()
               .ConfigureWebHostDefaults(webBuilder => webBuilder.UseTestServer());

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseContentRoot(AppContext.BaseDirectory);

        builder.ConfigureServices(services =>
        {
            services.AddRouting();
            services.AddZeeKayDaAuth(options => options.Issuer = "https://test.example.com");
        });

        builder.Configure(app =>
        {
            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapGet("/ping", () => Results.Ok("pong"));
                endpoints.MapZeeKayDaAuth();
            });
        });
    }
}

/// <summary>
/// A <see cref="WebApplicationFactory{TEntryPoint}"/> that injects an upstream middleware adding a
/// <c>Vary</c> response header, for testing additive Vary behaviour.
/// </summary>
internal sealed class TestWebAppFactoryWithVaryMiddleware : WebApplicationFactory<TestWebAppFactory>
{
    private readonly string _varyToAdd;
    private readonly Action<AuthorizationServerOptions>? _configureOptions;

    public TestWebAppFactoryWithVaryMiddleware(
        string varyToAdd,
        Action<AuthorizationServerOptions>? configureOptions = null)
    {
        _varyToAdd = varyToAdd;
        _configureOptions = configureOptions;
    }

    protected override IHostBuilder CreateHostBuilder()
        => Host.CreateDefaultBuilder()
               .ConfigureWebHostDefaults(webBuilder => webBuilder.UseTestServer());

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseContentRoot(AppContext.BaseDirectory);

        builder.ConfigureServices(services =>
        {
            services.AddRouting();
            services.AddZeeKayDaAuth(options =>
            {
                options.Issuer = "https://test.example.com";
                _configureOptions?.Invoke(options);
            });
        });

        var varyToAdd = _varyToAdd;
        builder.Configure(app =>
        {
            app.Use(async (ctx, next) =>
            {
                ctx.Response.Headers.Append("Vary", varyToAdd);
                await next();
            });
            app.UseRouting();
            app.UseEndpoints(endpoints => endpoints.MapZeeKayDaAuth());
        });
    }
}
