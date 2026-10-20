using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Reads a handler's options, through a virtual call rather than a reflective invoke, so a
/// validation failure surfaces as itself.
/// </summary>
internal static class HandlerOptions
{
    /// <summary>The handler's <see cref="AuthenticationHandler{TOptions}"/> options type, or <see langword="null"/>.</summary>
    public static Type? TypeOf(Type handlerType)
    {
        ArgumentNullException.ThrowIfNull(handlerType);

        for (var type = handlerType; type is not null; type = type.BaseType)
        {
            if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(AuthenticationHandler<>))
                return type.GenericTypeArguments[0];
        }

        return null;
    }

    /// <summary>
    /// The <c>ClaimsIssuer</c> a provider's options set: <see langword="null"/> when none is set, or the
    /// handler is not an <see cref="AuthenticationHandler{TOptions}"/> whose options can be read.
    /// </summary>
    public static string? ClaimsIssuerOf(IServiceProvider services, ProviderRegistration registration)
    {
        ArgumentNullException.ThrowIfNull(registration);

        return TypeOf(registration.HandlerType) is { } optionsType
            ? ((AuthenticationSchemeOptions)Resolve(services, optionsType, registration.Name)).ClaimsIssuer
            : null;
    }

    /// <summary>Resolves the options named <paramref name="name"/> of a type known only at runtime.</summary>
    public static object Resolve(IServiceProvider services, Type optionsType, string name)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(optionsType);
        ArgumentNullException.ThrowIfNull(name);

        return Resolver.For(optionsType).Resolve(services, name);
    }

    private abstract class Resolver
    {
        public static Resolver For(Type optionsType) =>
            (Resolver)Activator.CreateInstance(typeof(Resolver<>).MakeGenericType(optionsType))!;

        public abstract object Resolve(IServiceProvider services, string name);
    }

    private sealed class Resolver<TOptions> : Resolver
        where TOptions : class
    {
        public override object Resolve(IServiceProvider services, string name) =>
            services.GetRequiredService<IOptionsMonitor<TOptions>>().Get(name);
    }
}
