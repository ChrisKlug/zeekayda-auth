using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using ZeeKayDa.Auth.Logging;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Extensions;

/// <summary>
/// Extension methods for <see cref="IServiceCollection"/> to register ZeeKayDa.Auth core
/// infrastructure services.
/// </summary>
public static class ZeeKayDaAuthCoreServiceCollectionExtensions
{
    /// <summary>
    /// Registers ZeeKayDa.Auth core infrastructure — the <see cref="ISanitizingLogger{T}"/>
    /// implementation and the startup-verification runner — so that core services
    /// (<see cref="ZeeKayDa.Auth.Clients.InMemoryClientRepository"/>,
    /// <see cref="ZeeKayDa.Auth.Clients.Pbkdf2ClientSecretHasher"/>,
    /// <see cref="ZeeKayDa.Auth.Clients.ClientRegistrationValidator"/>) are resolvable without
    /// the full ASP.NET Core integration.
    /// </summary>
    /// <param name="services">The service collection to add services to.</param>
    /// <returns><paramref name="services"/> for chaining.</returns>
    /// <remarks>
    /// <c>AddZeeKayDaAuth()</c> in <c>ZeeKayDa.Auth.AspNetCore</c> calls this method
    /// automatically; you only need to call it directly when building a host that does not use
    /// the ASP.NET Core integration.
    /// </remarks>
    public static IServiceCollection AddZeeKayDaAuthCore(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        // AddOptions<T>() is idempotent. Registering here ensures that
        // SecretSanitizingLogger<T> can resolve IOptions<AuthorizationServerOptions> even when
        // AddZeeKayDaAuthCore() is called standalone without AddZeeKayDaAuth().
        services.AddOptions<AuthorizationServerOptions>();

        // Open-generic registration: every ZeeKayDa service that injects ISanitizingLogger<T>
        // automatically receives SecretSanitizingLogger<T>. TryAdd is idempotent across
        // repeated calls and allows AddZeeKayDaAuth() to override this registration.
        services.TryAddSingleton(typeof(ISanitizingLogger<>), typeof(SecretSanitizingLogger<>));

        // The single runner for every framework startup check. TryAddEnumerable keeps this
        // idempotent across repeated AddZeeKayDaAuthCore() calls (e.g. a provider package calling
        // it defensively alongside AddZeeKayDaAuth()'s own call).
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IHostedService, StartupVerificationHostedService>());

        // The sanitizing-logger shadow check must ship from the same registration call as the
        // runner, so that a host calling only AddZeeKayDaAuthCore() (e.g. a signing-provider
        // package wired without AddZeeKayDaAuth()) never gets a runner with an empty, vacuously
        // passing gate collection.
        services.TryAddSingleton(_ => new SanitizingLoggerClosedOverrideScanner(services));
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupVerificationGate, SanitizingLoggerRegistrationGate>());

        return services;
    }
}
