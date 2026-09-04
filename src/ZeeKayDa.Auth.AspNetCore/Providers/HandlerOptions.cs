using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace ZeeKayDa.Auth.AspNetCore.Providers;

/// <summary>
/// Reads an authentication handler's options at startup: the options type off the handler's base
/// chain, and the named instance resolved through a virtual call rather than a reflective invoke,
/// so a validation failure surfaces as itself. Nothing on the request path uses this.
/// </summary>
internal static class HandlerOptions
{
    /// <summary>
    /// The <c>TOptions</c> of the <see cref="AuthenticationHandler{TOptions}"/> in the handler's
    /// base chain, or <see langword="null"/> for a handler outside that hierarchy.
    /// </summary>
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
