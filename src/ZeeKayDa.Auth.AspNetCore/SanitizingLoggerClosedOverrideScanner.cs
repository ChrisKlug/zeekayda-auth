using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Scans a <see cref="IServiceCollection"/> for closed-generic <see cref="ISanitizingLogger{T}"/>
/// registrations, which the framework itself never adds.
/// </summary>
/// <remarks>
/// <c>AddZeeKayDaAuthCore()</c> registers only the open-generic
/// <c>ISanitizingLogger&lt;&gt;</c> (via <c>TryAddSingleton(typeof(ISanitizingLogger&lt;&gt;), ...)</c>).
/// A closed-generic registration for a specific <c>ISanitizingLogger&lt;SomeType&gt;</c> can only
/// have been added by the host, and it silently bypasses the redaction wrapper for that one type
/// regardless of registration order — .NET's DI container always prefers an exact closed-generic
/// match over an open-generic fallback. The constructor captures the <see cref="IServiceCollection"/>
/// reference itself (not a snapshot), so <see cref="FindClosedGenericOverrides"/> reflects every
/// registration added up to the point the container is built, however it is later invoked (see
/// <see cref="SanitizingLoggerRegistrationStartupValidator"/>).
/// </remarks>
internal sealed class SanitizingLoggerClosedOverrideScanner(IServiceCollection services)
{
    public IReadOnlyList<Type> FindClosedGenericOverrides() =>
        services
            .Select(descriptor => descriptor.ServiceType)
            .Where(serviceType => serviceType.IsGenericType
                && !serviceType.IsGenericTypeDefinition
                && serviceType.GetGenericTypeDefinition() == typeof(ISanitizingLogger<>))
            .Distinct()
            .ToArray();
}
