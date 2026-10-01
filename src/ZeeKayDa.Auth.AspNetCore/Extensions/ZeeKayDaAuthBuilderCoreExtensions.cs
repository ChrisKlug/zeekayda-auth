using ZeeKayDa.Auth.AspNetCore;
using ZeeKayDa.Auth.Claims;
using ZeeKayDa.Auth.Clients;
using ZeeKayDa.Auth.Stores;
using ZeeKayDa.Auth.Tokens;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// The <see cref="ZeeKayDa.Auth.ZeeKayDaAuthCoreBuilder"/> extensions that take a type argument of
/// their own, redeclared on <see cref="ZeeKayDaAuthBuilder"/> so a chain keeps its type.
/// </summary>
/// <remarks>
/// C# cannot infer a builder type argument while the caller supplies the other one, so these cannot
/// be generic over the builder the way the rest of the core extensions are. Each forwards to its
/// core counterpart; a new core extension with its own type argument needs its twin here.
/// </remarks>
public static class ZeeKayDaAuthBuilderCoreExtensions
{
    /// <inheritdoc cref="ZeeKayDaAuthBuilderSigningKeySourceExtensions.AddSigningKeySource{TSource}(ZeeKayDa.Auth.ZeeKayDaAuthCoreBuilder)"/>
    public static ZeeKayDaAuthBuilder AddSigningKeySource<TSource>(this ZeeKayDaAuthBuilder builder)
        where TSource : class, ISigningKeySource
    {
        ZeeKayDaAuthBuilderSigningKeySourceExtensions.AddSigningKeySource<TSource>(builder);
        return builder;
    }

    /// <inheritdoc cref="ZeeKayDaAuthBuilderClaimsExtensions.AddClaimsProvider{TProvider}(ZeeKayDa.Auth.ZeeKayDaAuthCoreBuilder)"/>
    public static ZeeKayDaAuthBuilder AddClaimsProvider<TProvider>(this ZeeKayDaAuthBuilder builder)
        where TProvider : class, IClaimsProvider
    {
        ZeeKayDaAuthBuilderClaimsExtensions.AddClaimsProvider<TProvider>(builder);
        return builder;
    }

    /// <inheritdoc cref="ZeeKayDaAuthBuilderHasherExtensions.AddClientSecretHasher{THasher}(ZeeKayDa.Auth.ZeeKayDaAuthCoreBuilder, bool)"/>
    public static ZeeKayDaAuthBuilder AddClientSecretHasher<THasher>(this ZeeKayDaAuthBuilder builder, bool isDefault = false)
        where THasher : class, IClientSecretHasher
    {
        ZeeKayDaAuthBuilderHasherExtensions.AddClientSecretHasher<THasher>(builder, isDefault);
        return builder;
    }

    /// <inheritdoc cref="ZeeKayDaAuthBuilderStoreExtensions.AddAuthorizationCodeStore{T}(ZeeKayDa.Auth.ZeeKayDaAuthCoreBuilder)"/>
    public static ZeeKayDaAuthBuilder AddAuthorizationCodeStore<T>(this ZeeKayDaAuthBuilder builder)
        where T : class, IAuthorizationCodeBackingStore
    {
        ZeeKayDaAuthBuilderStoreExtensions.AddAuthorizationCodeStore<T>(builder);
        return builder;
    }

    /// <inheritdoc cref="ZeeKayDaAuthBuilderStoreExtensions.AddRefreshTokenStore{T}(ZeeKayDa.Auth.ZeeKayDaAuthCoreBuilder)"/>
    public static ZeeKayDaAuthBuilder AddRefreshTokenStore<T>(this ZeeKayDaAuthBuilder builder)
        where T : class, IRefreshTokenBackingStore
    {
        ZeeKayDaAuthBuilderStoreExtensions.AddRefreshTokenStore<T>(builder);
        return builder;
    }
}
