using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// The registered <see cref="IClientAuthenticator"/>s, each with the methods it declared, read once.
/// </summary>
/// <remarks>
/// <see cref="IClientAuthenticator.AuthenticationMethods"/> is read here and nowhere else, so the
/// advertised methods, the startup check on the declarations and the token endpoint's per-request
/// check all see the same answer however the authenticator's own set changes afterwards.
/// </remarks>
internal sealed class RegisteredAuthenticators(IEnumerable<IClientAuthenticator> authenticators)
{
    /// <summary>Every registered authenticator, in registration order.</summary>
    public IReadOnlyList<RegisteredAuthenticator> All { get; } =
        authenticators.Select(authenticator => new RegisteredAuthenticator(authenticator)).ToList().AsReadOnly();

    /// <summary>The DI factory <c>AddZeeKayDaAuth</c> registers for <see cref="AdvertisedAuthMethods"/>.</summary>
    public static AdvertisedAuthMethods Advertise(IServiceProvider services) => new(
        services.GetRequiredService<RegisteredAuthenticators>().All.SelectMany(registered => registered.Methods),
        services.GetRequiredService<IOptions<AuthorizationServerOptions>>().Value.TokenEndpoint.AdvertisedAuthMethods);
}

/// <summary>One authenticator and a copy of the methods it declared when it was registered.</summary>
internal sealed class RegisteredAuthenticator
{
    private readonly HashSet<string> _methods;

    public RegisteredAuthenticator(IClientAuthenticator authenticator)
    {
        Authenticator = authenticator;
        Declared = authenticator.AuthenticationMethods?.ToList().AsReadOnly();
        _methods = new HashSet<string>(Declared?.OfType<string>() ?? [], StringComparer.Ordinal);
    }

    public IClientAuthenticator Authenticator { get; }

    /// <summary>
    /// The declaration exactly as read, for the startup check: <see langword="null"/> when the
    /// authenticator returned no set, and possibly holding null entries.
    /// </summary>
    public IReadOnlyList<string?>? Declared { get; }

    /// <summary>The non-null declared methods.</summary>
    public IEnumerable<string> Methods => _methods;

    /// <summary>Whether <paramref name="method"/> was declared, compared ordinally.</summary>
    public bool Performs(string method) => _methods.Contains(method);
}
