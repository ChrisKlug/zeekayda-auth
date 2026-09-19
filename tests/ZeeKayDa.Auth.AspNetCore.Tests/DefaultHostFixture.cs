using Microsoft.AspNetCore.Mvc.Testing;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// One default-configuration ASP.NET Core host, shared by every test that needs the real request
/// path: routing, the issuer-host constraint, the endpoint group's conventions, and the middleware
/// pipeline. Behaviour that a handler produces on its own belongs in a host-free
/// <see cref="EndpointHost"/> test instead.
/// </summary>
/// <remarks>
/// Shared through <see cref="DefaultHostCollection"/> so one host serves every class that uses it.
/// Tests against this host are read-only: a test that mutates server state, registers a client, or
/// advances a clock builds its own host, because xUnit runs the classes in a collection in sequence
/// but gives them no isolation from each other's side effects.
/// </remarks>
public sealed class DefaultHostFixture : IDisposable
{
    private readonly TestWebAppFactory _factory = new();
    private readonly List<HttpClient> _clients = [];

    /// <summary>A client addressing the host as its configured issuer, <c>https://test.example.com</c>.</summary>
    public HttpClient Client => ClientFor("https://test.example.com");

    /// <summary>The host's services, for reading a registered option or store.</summary>
    public IServiceProvider Services => _factory.Services;

    /// <summary>
    /// A client addressing the host at <paramref name="baseAddress"/>, for the tests that prove a
    /// request on the wrong host or the wrong scheme is refused.
    /// </summary>
    public HttpClient ClientFor(string baseAddress)
    {
        lock (_clients)
        {
            var existing = _clients.Find(c => c.BaseAddress?.ToString().TrimEnd('/') == baseAddress.TrimEnd('/'));
            if (existing is not null)
                return existing;

            var client = _factory.CreateClient(new WebApplicationFactoryClientOptions
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

        _factory.Dispose();
    }
}

/// <summary>
/// Groups every test class sharing <see cref="DefaultHostFixture"/> so the host is built once for
/// all of them.
/// </summary>
[CollectionDefinition(Name)]
public sealed class DefaultHostCollection : ICollectionFixture<DefaultHostFixture>
{
    /// <summary>The collection name to put on a test class with <c>[Collection]</c>.</summary>
    public const string Name = "default host";
}
