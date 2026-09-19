using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ZeeKayDa.Auth.Extensions;
using ZeeKayDa.Auth.AspNetCore.Endpoints;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Stores;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// A ZeeKayDa.Auth service container with no web host, for testing an endpoint's behaviour given a
/// request: status code, headers, and body.
/// </summary>
/// <remarks>
/// <para>
/// Registers what a real host registers, so the endpoint under test resolves the same collaborators
/// it would in production, and invokes its handler the way minimal APIs do — every parameter other
/// than <see cref="HttpContext"/> comes from the container. Nothing about routing is involved, so a
/// behaviour carried by the route table or the middleware pipeline cannot be tested here: the
/// issuer-host constraint, path-prefixed discovery routes, <c>AllowAnonymous</c> against a host-wide
/// fallback policy, and CORS preflight all need a real host.
/// </para>
/// <para>
/// <see cref="Default"/> is shared by every test wanting the default configuration. A test that needs
/// its own stores, clock, or clients constructs its own instance instead, which gives it fresh state
/// by construction — there is no shared mutable state to collide over.
/// </para>
/// </remarks>
internal sealed class EndpointHost : IDisposable
{
    private static readonly Lazy<EndpointHost> LazyDefault = new(() => new EndpointHost());

    private static readonly ConcurrentDictionary<string, Lazy<EndpointHost>> SharedHosts = new(StringComparer.Ordinal);

    private readonly ServiceProvider _services;
    private readonly Lazy<Task> _started;

    /// <summary>
    /// Initialises a container with the default test configuration: issuer
    /// <c>https://test.example.com</c>, one public client <c>test-client</c>, in-memory stores, a
    /// test signing key source, and a claims provider that returns no claims.
    /// </summary>
    /// <param name="configureOptions">Applied on top of the default options.</param>
    /// <param name="configureBuilder">
    /// Applied after <c>AddZeeKayDaAuth()</c>, before the fallback store and client registrations, so
    /// a store or repository registered here wins.
    /// </param>
    public EndpointHost(
        Action<AuthorizationServerOptions>? configureOptions = null,
        Action<ZeeKayDaAuthBuilder>? configureBuilder = null)
    {
        var services = new ServiceCollection();

        services.AddLogging();
        services.AddSingleton<IHostEnvironment>(new TestHostEnvironment());

        var authBuilder = services.AddZeeKayDaAuth(options =>
        {
            options.Issuer = "https://test.example.com";
            options.TokenEndpoint.AuthMethodsSupported.Add(TokenEndpointAuthMethods.None);
            options.AuthorizationEndpoint.Interaction.LoginPath = "/account/login";
            options.AuthorizationEndpoint.Interaction.ConsentPath = "/account/consent";

            configureOptions?.Invoke(options);
        });

        configureBuilder?.Invoke(authBuilder);

        if (!authBuilder.Services.Any(d => d.ServiceType == typeof(IClientRepository)))
            authBuilder.AddInMemoryClients(clients =>
                clients.AddPublic("test-client", ["https://test.example.com/callback"], [], ["openid"]));

        if (!authBuilder.Services.Any(d => d.ServiceType == typeof(IAuthorizationCodeStore)))
            authBuilder.AddInMemoryStores(allowOutsideDevelopment: true);

        authBuilder.AddTestSigningKeys();
        authBuilder.AddTestClaimsProvider();

        // Scope validation on, unlike the Production web hosts, so a singleton capturing a scoped
        // service throws here instead of silently holding the first scope's instance.
        _services = services.BuildServiceProvider(new ServiceProviderOptions
        {
            ValidateScopes = true,
            ValidateOnBuild = false,
        });

        _started = new Lazy<Task>(StartAsync);
    }

    /// <summary>A container with the default test configuration, shared across the test project.</summary>
    public static EndpointHost Default => LazyDefault.Value;

    /// <summary>
    /// Returns the container cached under <paramref name="key"/>, building it on first use. Several
    /// tests asserting different things about one configuration then pay for it once.
    /// </summary>
    /// <param name="key">
    /// Names the configuration. Two callers using the same key get the same container, and the
    /// second caller's delegates are never invoked — so the key must describe the configuration, not
    /// the test.
    /// </param>
    /// <param name="configureOptions">Applied on top of the default options, on first use only.</param>
    /// <param name="configureBuilder">Applied after <c>AddZeeKayDaAuth()</c>, on first use only.</param>
    /// <remarks>
    /// For a configuration the tests only read from. A test that writes to a store, registers a
    /// client, or advances a clock constructs its own <see cref="EndpointHost"/> instead, so its state
    /// cannot reach a sibling test.
    /// </remarks>
    public static EndpointHost Shared(
        string key,
        Action<AuthorizationServerOptions>? configureOptions = null,
        Action<ZeeKayDaAuthBuilder>? configureBuilder = null)
        => SharedHosts.GetOrAdd(
            key,
            _ => new Lazy<EndpointHost>(() => new EndpointHost(configureOptions, configureBuilder))).Value;

    /// <summary>The container the endpoint under test resolves from.</summary>
    public IServiceProvider Services => _services;

    /// <summary>Resolves a registered service, for arranging state a handler will read.</summary>
    public T Resolve<T>() where T : notnull => _services.GetRequiredService<T>();

    /// <summary>
    /// Runs the framework's startup phase — the gates, verifiers, and activators a host runs — once
    /// for this container, and awaits the same result on every later call.
    /// </summary>
    /// <remarks>
    /// <see cref="InvokeAsync{TEndpoint}(Func{TEndpoint, Delegate}, TestRequest)"/> calls this itself.
    /// Call it directly when the test arranges state before invoking anything, or when the assertion
    /// is that startup fails.
    /// </remarks>
    public Task EnsureStartedAsync() => _started.Value;

    /// <summary>Begins a <c>GET</c> request at <paramref name="pathAndQuery"/>.</summary>
    public TestRequest Get(string pathAndQuery) => new(HttpMethods.Get, pathAndQuery);

    /// <summary>Begins a <c>POST</c> request at <paramref name="pathAndQuery"/>.</summary>
    public TestRequest Post(string pathAndQuery) => new(HttpMethods.Post, pathAndQuery);

    /// <summary>Begins a request at <paramref name="pathAndQuery"/> using <paramref name="method"/>.</summary>
    public TestRequest Request(string method, string pathAndQuery) => new(method, pathAndQuery);

    /// <summary>
    /// Invokes <paramref name="handler"/> on the endpoint resolved from this container, against
    /// <paramref name="request"/>, and returns what the handler wrote to the response.
    /// </summary>
    /// <typeparam name="TEndpoint">The endpoint type to resolve and invoke a handler on.</typeparam>
    /// <param name="handler">
    /// Selects the handler as a method group, for example <c>e =&gt; e.Handle</c>. Every parameter
    /// other than <see cref="HttpContext"/> is resolved from the container, as minimal APIs do.
    /// </param>
    /// <param name="request">The request to invoke the handler against.</param>
    /// <returns>The response the handler produced.</returns>
    public async Task<HttpResponseMessage> InvokeAsync<TEndpoint>(
        Func<TEndpoint, Delegate> handler,
        TestRequest request)
        where TEndpoint : notnull
    {
        ArgumentNullException.ThrowIfNull(handler);
        ArgumentNullException.ThrowIfNull(request);

        await EnsureStartedAsync().ConfigureAwait(false);

        await using var scope = _services.CreateAsyncScope();

        var context = request.Build(scope.ServiceProvider);
        var result = await InvokeHandlerAsync(handler(ResolveEndpoint<TEndpoint>()), context, scope.ServiceProvider)
            .ConfigureAwait(false);

        await result.ExecuteAsync(context).ConfigureAwait(false);

        return ReadResponse(context);
    }

    /// <inheritdoc/>
    public void Dispose() => _services.Dispose();

    /// <summary>
    /// Runs every registered <see cref="IHostedService"/>, which is how the framework's startup
    /// verification runs in a real host — and the only thing that initialises the signing key ring,
    /// so the discovery document and JWKS have nothing to serve until it has run.
    /// </summary>
    private async Task StartAsync()
    {
        foreach (var service in _services.GetServices<IHostedService>())
            await service.StartAsync(CancellationToken.None).ConfigureAwait(false);
    }

    /// <summary>
    /// Resolves the endpoint to invoke a handler on. An endpoint is registered against
    /// <c>IZeeKayDaEndpoint</c> rather than its own type, so the concrete instance comes out of that
    /// enumeration; anything else resolves directly.
    /// </summary>
    private TEndpoint ResolveEndpoint<TEndpoint>() where TEndpoint : notnull
    {
        var registered = _services.GetServices<IZeeKayDaEndpoint>().OfType<TEndpoint>().ToArray();

        return registered.Length switch
        {
            1 => registered[0],
            0 => Resolve<TEndpoint>(),
            _ => throw new InvalidOperationException(
                $"{registered.Length} endpoints of type {typeof(TEndpoint).Name} are registered."),
        };
    }

    private static async Task<IResult> InvokeHandlerAsync(
        Delegate handler, HttpContext context, IServiceProvider services)
    {
        var arguments = handler.Method.GetParameters()
            .Select(p => p.ParameterType == typeof(HttpContext)
                ? context
                : services.GetRequiredService(p.ParameterType))
            .ToArray();

        var returned = handler.DynamicInvoke(arguments);

        return returned switch
        {
            IResult result => result,
            Task<IResult> task => await task.ConfigureAwait(false),
            ValueTask<IResult> task => await task.ConfigureAwait(false),
            null => throw new InvalidOperationException(
                $"{handler.Method.Name} returned null rather than an IResult."),
            _ => throw new InvalidOperationException(
                $"{handler.Method.Name} returns {returned.GetType().FullName}, which is not an IResult."),
        };
    }

    private static HttpResponseMessage ReadResponse(HttpContext context)
    {
        var body = (MemoryStream)context.Response.Body;

        var message = new HttpResponseMessage((HttpStatusCode)context.Response.StatusCode)
        {
            Content = new ByteArrayContent(body.ToArray()),
        };

        // Content-Type and Content-Length belong on the content, and TryAddWithoutValidation on the
        // message rejects them, which is what routes each header to the right collection.
        foreach (var header in context.Response.Headers)
        {
            var values = (IEnumerable<string?>)header.Value;
            if (!message.Headers.TryAddWithoutValidation(header.Key, values))
                message.Content.Headers.TryAddWithoutValidation(header.Key, values);
        }

        return message;
    }

    /// <summary>
    /// Reports "Production" as the current environment, matching the web hosts these tests replace —
    /// the in-memory store guard and the development signing keys both branch on it.
    /// </summary>
    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Production;

        public string ApplicationName { get; set; } = "ZeeKayDa.Auth.AspNetCore.Tests";

        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;

        public IFileProvider ContentRootFileProvider { get; set; } =
            new PhysicalFileProvider(AppContext.BaseDirectory);
    }
}

/// <summary>
/// A request under construction, for handing to
/// <see cref="EndpointHost.InvokeAsync{TEndpoint}(Func{TEndpoint, Delegate}, TestRequest)"/>.
/// </summary>
internal sealed class TestRequest
{
    private readonly string _method;
    private readonly string _pathAndQuery;
    private readonly Dictionary<string, string> _headers = new(StringComparer.OrdinalIgnoreCase);

    private string _host = "test.example.com";
    private string _scheme = "https";
    private byte[]? _body;
    private string? _contentType;

    internal TestRequest(string method, string pathAndQuery)
    {
        _method = method;
        _pathAndQuery = pathAndQuery;
    }

    /// <summary>Sets the <c>Host</c> header, for the tests that vary which host is addressed.</summary>
    public TestRequest WithHost(string host)
    {
        _host = host;
        return this;
    }

    /// <summary>Sets the request scheme, for the tests that address the endpoint over plain HTTP.</summary>
    public TestRequest WithScheme(string scheme)
    {
        _scheme = scheme;
        return this;
    }

    /// <summary>Adds a request header. A repeated name appends, so a duplicate-header test can set two.</summary>
    public TestRequest WithHeader(string name, string value)
    {
        _headers[name] = _headers.TryGetValue(name, out var existing) ? $"{existing},{value}" : value;
        return this;
    }

    /// <summary>Sets an <c>application/x-www-form-urlencoded</c> body from <paramref name="fields"/>.</summary>
    public TestRequest WithForm(IEnumerable<KeyValuePair<string, string>> fields)
    {
        ArgumentNullException.ThrowIfNull(fields);

        var encoded = string.Join('&', fields.Select(
            f => $"{Uri.EscapeDataString(f.Key)}={Uri.EscapeDataString(f.Value)}"));

        _body = Encoding.UTF8.GetBytes(encoded);
        _contentType = "application/x-www-form-urlencoded";
        return this;
    }

    /// <summary>Sets a raw body, for the tests that send a malformed or unexpected content type.</summary>
    public TestRequest WithBody(string body, string contentType)
    {
        _body = Encoding.UTF8.GetBytes(body);
        _contentType = contentType;
        return this;
    }

    internal HttpContext Build(IServiceProvider requestServices)
    {
        var context = new DefaultHttpContext { RequestServices = requestServices };

        var queryIndex = _pathAndQuery.IndexOf('?', StringComparison.Ordinal);

        context.Request.Method = _method;
        context.Request.Scheme = _scheme;
        context.Request.Host = new HostString(_host);
        context.Request.Path = queryIndex < 0 ? _pathAndQuery : _pathAndQuery[..queryIndex];
        context.Request.QueryString = queryIndex < 0
            ? QueryString.Empty
            : new QueryString(_pathAndQuery[queryIndex..]);

        foreach (var header in _headers)
            context.Request.Headers[header.Key] = header.Value;

        if (_body is not null)
        {
            context.Request.Body = new MemoryStream(_body);
            context.Request.ContentLength = _body.Length;
            context.Request.ContentType = _contentType;
        }

        context.Response.Body = new MemoryStream();

        return context;
    }
}
