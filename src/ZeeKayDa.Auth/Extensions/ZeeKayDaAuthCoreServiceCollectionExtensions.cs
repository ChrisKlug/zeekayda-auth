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
    /// implementation, the startup-verification runner and its gates, the signing-key-ring
    /// startup activator, and the per-<see cref="TokenKind"/> <see cref="ITokenIssuer"/>
    /// registrations — so that core services are resolvable without the full ASP.NET Core
    /// integration.
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

        // Registered here as well as by AddZeeKayDaSigningKeySource, and not for position — the
        // activator phase makes order irrelevant. It is for coverage: StaticSigningKeyRing has a
        // public constructor, so a host can register an ISigningKeyRing itself without going
        // through AddZeeKayDaSigningKeySource, and without this that ring would never be
        // initialized or self-tested. A silent no-op when no ring is registered at all.
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IStartupActivator, SigningKeyRingStartupVerifier>());

        // The issuer for each TokenKind is a keyed service, so the host can swap how one kind is
        // issued without touching the other — e.g. opaque access tokens alongside JWT ID tokens
        // once a reference-token issuer exists. TryAdd keeps a host's own earlier registration.
        services.TryAddKeyedSingleton<ITokenIssuer, JwtTokenIssuer>(TokenKind.AccessToken);
        services.TryAddKeyedSingleton<ITokenIssuer, JwtTokenIssuer>(TokenKind.IdToken);

        return services;
    }
}
