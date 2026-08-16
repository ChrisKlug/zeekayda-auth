using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth.Logging;

namespace ZeeKayDa.Auth.AspNetCore;

/// <summary>
/// Scans a <see cref="IServiceCollection"/> for closed-generic <see cref="ISanitizingLogger{T}"/>
/// registrations, which the framework itself never adds.
/// </summary>
/// <remarks>
/// A closed-generic <c>ISanitizingLogger&lt;SomeType&gt;</c> registration can only have been
/// added by the host, and silently bypasses the redaction wrapper for that type — .NET's DI
/// container always prefers an exact closed-generic match over an open-generic fallback. The
/// constructor captures the <see cref="IServiceCollection"/> reference itself, so
/// <see cref="FindClosedGenericOverrides"/> reflects every registration added up to the point
/// it's invoked.
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
