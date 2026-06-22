using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Stores;
using ZeeKayDa.Auth.Tokens;

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

                // Advertise "none" so the public test client passes the subset validation.
                options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);

                // Integration test hosts run as "Production" by default; allow in-memory stores
                // so the startup guard does not block test startup.
                options.AllowInMemoryStoresOutsideDevelopment = true;

                // Allow per-test overrides (e.g. path-bearing issuer, AllowInsecureIssuer, etc.)
                _configureOptions?.Invoke(options);
            });

            // Register a minimal in-memory client repository so the startup validator passes.
            // Individual tests that override _configureBuilder may call AddInMemoryClients
            // themselves; the TryAdd pattern ensures it is only registered once.
            authBuilder.AddInMemoryClients(clients =>
                clients.AddPublic("test-client",
                    ["https://test.example.com/callback"],
                    [],
                    ["openid"]));

            // Invoke the per-test builder delegate first so that any custom store registrations
            // it makes are visible before we decide whether to fall back to in-memory stores.
            _configureBuilder?.Invoke(authBuilder);

            // Register in-memory stores so the TokenStorePresenceValidator passes at startup,
            // but only when _configureBuilder has not already registered stores. This avoids
            // a ThrowIfAlreadyRegistered exception when the caller brings its own stores.
            if (!authBuilder.Services.Any(d => d.ServiceType == typeof(IAuthorizationCodeStore)))
                authBuilder.AddInMemoryStores();
        });

        builder.Configure(app =>
        {
            app.UseRouting();
            app.UseEndpoints(endpoints => endpoints.MapZeeKayDaAuth());
        });
    }
}

/// <summary>
/// A <see cref="WebApplicationFactory{TEntryPoint}"/> that sets a fixed
/// <see cref="HttpContext.Connection.RemoteIpAddress"/> on every request, for testing the
/// HTTPS loopback guard.
/// </summary>
internal sealed class TestWebAppFactoryWithRemoteIp : WebApplicationFactory<TestWebAppFactory>
{
    private readonly IPAddress? _remoteIpAddress;
    private readonly Action<AuthorizationServerOptions>? _configureOptions;

    public TestWebAppFactoryWithRemoteIp(
        IPAddress? remoteIpAddress,
        Action<AuthorizationServerOptions>? configureOptions = null)
    {
        _remoteIpAddress = remoteIpAddress;
        _configureOptions = configureOptions;
    }

    protected override IHostBuilder CreateHostBuilder()
        => Host.CreateDefaultBuilder()
               .ConfigureWebHostDefaults(webBuilder => webBuilder.UseTestServer());

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseContentRoot(AppContext.BaseDirectory);
        var remoteIpAddress = _remoteIpAddress;

        builder.ConfigureServices(services =>
        {
            services.AddRouting();
            services.AddZeeKayDaAuth(options =>
            {
                options.Issuer = "http://localhost:5000";
                options.AllowInsecureIssuer = true;
                // Advertise "none" so the public test client passes the subset validation.
                options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
                // Integration test hosts run as "Production" by default; allow in-memory stores.
                options.AllowInMemoryStoresOutsideDevelopment = true;
                _configureOptions?.Invoke(options);
            }).AddInMemoryClients(clients =>
                clients.AddPublic("test-client",
                    ["https://test.example.com/callback"],
                    [],
                    ["openid"]))
              .AddInMemoryStores();
        });

        builder.Configure(app =>
        {
            app.Use(async (ctx, next) =>
            {
                ctx.Connection.RemoteIpAddress = remoteIpAddress;
                await next();
            });
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
            services.AddZeeKayDaAuth(options =>
            {
                options.Issuer = "https://test.example.com";
                options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
                // Integration test hosts run as "Production" by default; allow in-memory stores.
                options.AllowInMemoryStoresOutsideDevelopment = true;
            }).AddInMemoryClients(clients =>
                clients.AddPublic("test-client",
                    ["https://test.example.com/callback"],
                    [],
                    ["openid"]))
              .AddInMemoryStores();
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
                options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
                // Integration test hosts run as "Production" by default; allow in-memory stores.
                options.AllowInMemoryStoresOutsideDevelopment = true;
                _configureOptions?.Invoke(options);
            }).AddInMemoryClients(clients =>
                clients.AddPublic("test-client",
                    ["https://test.example.com/callback"],
                    [],
                    ["openid"]))
              .AddInMemoryStores();
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
