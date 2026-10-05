using Microsoft.Extensions.DependencyInjection;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.StartupVerification;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// Startup check that every registered <see cref="IClientAuthenticator"/> declares well-formed
/// methods, none of them the reserved <c>none</c>, and none declared by another. What the server
/// advertises from those declarations is checked by the core's <c>AdvertisedAuthMethodsActivator</c>.
/// </summary>
/// <remarks>
/// An activator rather than a verifier, by the mechanical rule: it constructs every registered
/// authenticator, and those are the host's own. It is deliberately not an
/// <c>IValidateOptions&lt;AuthorizationServerOptions&gt;</c>, which would make the first read of
/// the server options construct part of the service graph. The authenticators are built by whichever
/// startup check first needs them — this one, the advertised-methods check, or the client
/// repository's — so one that fails to construct is reported against that check, with the
/// construction failure as its root cause either way.
/// </remarks>
internal sealed class ClientAuthenticatorActivator(IServiceProvider services) : IStartupActivator
{
    /// <inheritdoc/>
    public string Name => "ClientAuthenticator";

    /// <inheritdoc/>
    public Task VerifyAsync(StartupVerificationContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var declaringTypeByMethod = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var registered in services.GetRequiredService<RegisteredAuthenticators>().All)
            CheckDeclaration(context, declaringTypeByMethod, registered);

        return Task.CompletedTask;
    }

    private static void CheckDeclaration(
        StartupVerificationContext context,
        Dictionary<string, string> declaringTypeByMethod,
        RegisteredAuthenticator registered)
    {
        var typeName = registered.Authenticator.GetType().Name;
        if (registered.Declared is not { } methods)
        {
            Report(context, NullMethod(typeName));
            return;
        }

        foreach (var method in methods)
        {
            if (MalformedMethod(typeName, method) is { } malformed)
                Report(context, malformed);
            else
                CheckReservedAndOverlap(context, declaringTypeByMethod, typeName, method!);
        }
    }

    private static void Report(StartupVerificationContext context, ZeeKayDaConfigurationFailure failure) =>
        context.AddFailure(failure.Code, failure.Message);

    /// <summary>
    /// Whether a method string is unusable as a name at all. Every one of these would pass the
    /// ordinal comparisons the server uses, and so fail silently at runtime instead of at startup.
    /// </summary>
    private static ZeeKayDaConfigurationFailure? MalformedMethod(string typeName, string? method)
    {
        if (method is null)
            return NullMethod(typeName);

        // Never advertised, so the server would start unable to perform it.
        if (TokenEndpointAuthMethodRules.IsBlank(method) || TokenEndpointAuthMethodRules.HasControlCharacters(method))
        {
            return new(
                "authenticators.method_malformed",
                $"{typeName} declares an auth method that is blank or contains control characters. " +
                $"Method strings must match exactly — use the constants in {nameof(TokenEndpointAuthMethods)}.");
        }

        // " none" or "client_secret_basic " would never match what a client presents.
        if (TokenEndpointAuthMethodRules.HasSurroundingWhitespace(method))
        {
            return new(
                "authenticators.method_whitespace",
                $"{typeName} declares auth method '{method}' which has leading or trailing " +
                "whitespace. Method strings must match exactly — use the constants in " +
                $"{nameof(TokenEndpointAuthMethods)}.");
        }

        // "Client_Secret_Basic" would collide at runtime with the built-in authenticator's
        // CanHandle, producing a silent invalid_client.
        if (_canonicalMethodNames.TryGetValue(method, out var canonical) &&
            !string.Equals(method, canonical, StringComparison.Ordinal))
        {
            return new(
                "authenticators.method_casing",
                $"{typeName} declares auth method '{method}' which differs from the canonical " +
                $"form '{canonical}' in casing. Use the exact constant from " +
                $"{nameof(TokenEndpointAuthMethods)} to avoid silent runtime mismatches.");
        }

        return null;
    }

    private static void CheckReservedAndOverlap(
        StartupVerificationContext context,
        Dictionary<string, string> declaringTypeByMethod,
        string typeName,
        string method)
    {
        if (string.Equals(method, TokenEndpointAuthMethods.None, StringComparison.Ordinal))
        {
            context.AddFailure(
                "authenticators.none_declared",
                $"{typeName} declares '{TokenEndpointAuthMethods.None}' in AuthenticationMethods. " +
                $"'{TokenEndpointAuthMethods.None}' is reserved for the CompositeClientAuthenticator " +
                "fallback and must not be declared by any IClientAuthenticator.");
        }
        else if (declaringTypeByMethod.TryGetValue(method, out var existingType))
        {
            context.AddFailure(
                "authenticators.method_overlap",
                $"Both {existingType} and {typeName} declare auth method '{method}'. " +
                "Each method must be handled by exactly one IClientAuthenticator.");
        }
        else
        {
            declaringTypeByMethod[method] = typeName;
        }
    }

    private static ZeeKayDaConfigurationFailure NullMethod(string typeName) => new(
        "authenticators.method_null",
        $"{typeName} returns a null AuthenticationMethods set or a null entry in it. Declare the " +
        $"methods it performs, using the constants in {nameof(TokenEndpointAuthMethods)}.");

    // Case-insensitive map of framework-handled method strings to their canonical form.
    private static readonly IReadOnlyDictionary<string, string> _canonicalMethodNames =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [TokenEndpointAuthMethods.ClientSecretBasic] = TokenEndpointAuthMethods.ClientSecretBasic,
            [TokenEndpointAuthMethods.ClientSecretPost] = TokenEndpointAuthMethods.ClientSecretPost,
            [TokenEndpointAuthMethods.None] = TokenEndpointAuthMethods.None,
        };
}
