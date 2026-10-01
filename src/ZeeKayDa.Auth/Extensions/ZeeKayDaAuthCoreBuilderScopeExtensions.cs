using Microsoft.Extensions.DependencyInjection.Extensions;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Scopes;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering scope repositories with <see cref="ZeeKayDaAuthCoreBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthCoreBuilderScopeExtensions
{
    /// <summary>
    /// Registers an in-memory scope repository.
    /// </summary>
    /// <typeparam name="TBuilder">The builder type, returned so a chain keeps it.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="scopes">The scope definitions to register.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="scopes"/> is
    /// <see langword="null"/>.
    /// </exception>
    public static TBuilder AddInMemoryScopes<TBuilder>(
        this TBuilder builder,
        IEnumerable<ScopeDefinition> scopes)
        where TBuilder : ZeeKayDaAuthCoreBuilder
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(scopes);

        builder.Services.Replace(
            ServiceDescriptor.Singleton<IScopeRepository>(new InMemoryScopeRepository(scopes)));

        return builder;
    }
}
