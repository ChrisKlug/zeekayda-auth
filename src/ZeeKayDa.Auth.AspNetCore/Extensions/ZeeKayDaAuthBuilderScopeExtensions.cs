using Microsoft.Extensions.DependencyInjection.Extensions;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Scopes;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering scope repositories with <see cref="ZeeKayDaAuthBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthBuilderScopeExtensions
{
    /// <summary>
    /// Registers an in-memory scope repository.
    /// </summary>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <param name="scopes">The scope definitions to register.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> or <paramref name="scopes"/> is
    /// <see langword="null"/>.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddInMemoryScopes(
        this ZeeKayDaAuthBuilder builder,
        IEnumerable<ScopeDefinition> scopes)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(scopes);

        builder.Services.Replace(
            ServiceDescriptor.Singleton<IScopeRepository>(new InMemoryScopeRepository(scopes)));

        return builder;
    }
}
