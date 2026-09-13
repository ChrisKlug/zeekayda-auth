using Microsoft.Extensions.DependencyInjection.Extensions;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Claims;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for registering the claims provider with <see cref="ZeeKayDaAuthBuilder"/>.
/// </summary>
public static class ZeeKayDaAuthBuilderClaimsExtensions
{
    /// <summary>
    /// Registers <typeparamref name="TProvider"/> as the host's <see cref="IClaimsProvider"/>,
    /// the source of every subject claim a token carries.
    /// </summary>
    /// <typeparam name="TProvider">The provider implementation.</typeparam>
    /// <param name="builder">The ZeeKayDa.Auth builder.</param>
    /// <returns>The <paramref name="builder"/> so calls can be chained.</returns>
    /// <remarks>
    /// The provider is registered scoped, so it may take a per-request database context. A host
    /// without a registered provider fails startup; there is no default. A later call replaces an
    /// earlier registration.
    /// </remarks>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="builder"/> is <see langword="null"/>.
    /// </exception>
    public static ZeeKayDaAuthBuilder AddClaimsProvider<TProvider>(this ZeeKayDaAuthBuilder builder)
        where TProvider : class, IClaimsProvider
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.Services.Replace(ServiceDescriptor.Scoped<IClaimsProvider, TProvider>());

        return builder;
    }
}
