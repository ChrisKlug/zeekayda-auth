using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// One ASP.NET Core host per configuration, shared by every test needing the real request path:
/// routing, the issuer-host constraint, the endpoint group's conventions, and the middleware
/// pipeline. Behaviour a handler produces on its own belongs in a host-free
/// <see cref="EndpointHost"/> test instead.
/// </summary>
/// <remarks>
/// <para>
/// The host is built on first use rather than in the constructor, so a class joining
/// <see cref="DefaultHostCollection"/> pays only for the hosts its own tests actually reach.
/// </para>
/// <para>
/// Tests against a shared host are read-only. A test that mutates server state — issuing a code,
/// registering a client, advancing a clock — builds its own host, because xUnit gives the classes in
/// a collection no isolation from each other's side effects.
/// </para>
/// </remarks>
public abstract class SharedHostFixture : IDisposable
{
    private readonly Lock _gate = new();
    private readonly List<HttpClient> _clients = [];

    private WebApplicationFactory<TestWebAppFactory>? _factory;

    /// <summary>A client addressing the host at <see cref="DefaultBaseAddress"/>.</summary>
    public HttpClient Client => ClientFor(DefaultBaseAddress);

    /// <summary>The host's services, for reading a registered option or store.</summary>
    public IServiceProvider Services => Factory.Services;

    /// <summary>The address this host answers as — its configured issuer.</summary>
    protected abstract string DefaultBaseAddress { get; }

    private WebApplicationFactory<TestWebAppFactory> Factory
    {
        get
        {
            lock (_gate)
                return _factory ??= CreateFactory();
        }
    }

    /// <summary>
    /// A client addressing the host at <paramref name="baseAddress"/>, for the tests that prove a
    /// request on the wrong host or the wrong scheme is refused. Clients are reused per address.
    /// </summary>
    /// <param name="baseAddress">The base address the client should send to.</param>
    /// <returns>A client bound to <paramref name="baseAddress"/>.</returns>
    public HttpClient ClientFor(string baseAddress)
    {
        ArgumentNullException.ThrowIfNull(baseAddress);

        var factory = Factory;

        lock (_gate)
        {
            var existing = _clients.Find(
                c => c.BaseAddress?.ToString().TrimEnd('/') == baseAddress.TrimEnd('/'));

            if (existing is not null)
                return existing;

            var client = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri(baseAddress),
            });

            _clients.Add(client);
            return client;
        }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        foreach (var client in _clients)
            client.Dispose();

        _factory?.Dispose();
        GC.SuppressFinalize(this);
    }

    /// <summary>Builds this fixture's host. Called once, on first use.</summary>
    /// <returns>The factory whose host the fixture's tests run against.</returns>
    protected abstract WebApplicationFactory<TestWebAppFactory> CreateFactory();
}

/// <summary>The default test configuration: issuer <c>https://test.example.com</c>.</summary>
public sealed class DefaultHostFixture : SharedHostFixture
{
    /// <inheritdoc/>
    protected override string DefaultBaseAddress => "https://test.example.com";

    /// <inheritdoc/>
    protected override WebApplicationFactory<TestWebAppFactory> CreateFactory() => new TestWebAppFactory();
}

/// <summary>
/// A path-bearing issuer, <c>https://test.example.com/tenant1</c> — the configuration that proves
/// discovery registers under the issuer's path, as OIDC Discovery 1.0 §4.1 and RFC 9207 §4 require.
/// </summary>
public sealed class TenantIssuerHostFixture : SharedHostFixture
{
    /// <summary>The issuer this host is configured with, path included.</summary>
    public const string Issuer = "https://test.example.com/tenant1";

    /// <inheritdoc/>
    protected override string DefaultBaseAddress => "https://test.example.com";

    /// <inheritdoc/>
    protected override WebApplicationFactory<TestWebAppFactory> CreateFactory()
        => new TestWebAppFactory(opts => opts.Issuer = Issuer);
}

/// <summary>
/// A host whose authorization <c>FallbackPolicy</c> requires an authenticated user, for proving the
/// public metadata endpoints stay anonymously readable.
/// </summary>
public sealed class FallbackPolicyHostFixture : SharedHostFixture
{
    /// <inheritdoc/>
    protected override string DefaultBaseAddress => "https://test.example.com";

    /// <inheritdoc/>
    protected override WebApplicationFactory<TestWebAppFactory> CreateFactory()
        => new TestWebAppFactoryWithFallbackAuthorizationPolicy();
}

/// <summary>
/// A loopback host with <c>AllowInsecureIssuer</c>, issuer <c>http://localhost:5000</c>, for the
/// tests that prove plain HTTP is served to loopback and refused to anything else.
/// </summary>
public sealed class LoopbackHostFixture : SharedHostFixture
{
    /// <inheritdoc/>
    protected override string DefaultBaseAddress => "http://localhost:5000";

    /// <inheritdoc/>
    protected override WebApplicationFactory<TestWebAppFactory> CreateFactory()
        => new TestWebAppFactoryWithRemoteIp(IPAddress.Loopback);
}

/// <summary>
/// Groups the test classes that share the read-only hosts, so each host is built once for all of
/// them and only if one of their tests reaches it.
/// </summary>
[CollectionDefinition(Name)]
public sealed class DefaultHostCollection :
    ICollectionFixture<DefaultHostFixture>,
    ICollectionFixture<TenantIssuerHostFixture>,
    ICollectionFixture<FallbackPolicyHostFixture>,
    ICollectionFixture<LoopbackHostFixture>
{
    /// <summary>The collection name to put on a test class with <c>[Collection]</c>.</summary>
    public const string Name = "shared hosts";
}
