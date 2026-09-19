using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// Startup check that ensures every method in <c>AuthMethodsSupported</c> is covered by
/// exactly one registered <see cref="IClientAuthenticator"/>, and that no authenticator
/// misconfigures the reserved <c>none</c> method or overlaps with another authenticator.
/// </summary>
/// <remarks>
/// An activator rather than a verifier, by the mechanical rule: it constructs every registered
/// authenticator, and those are the host's own. It is deliberately not an
/// <c>IValidateOptions&lt;AuthorizationServerOptions&gt;</c>, which would make the first read of
/// the server options construct part of the service graph. An authenticator that fails to
/// construct is not caught here: the runner reports it as a startup failure naming the exception.
/// </remarks>
internal sealed class AuthenticatorCoverageValidator : IStartupActivator
{
    private readonly IOptions<AuthorizationServerOptions> _options;

    public AuthenticatorCoverageValidator(IOptions<AuthorizationServerOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
    }

    /// <inheritdoc/>
    public string Name => "AuthenticatorCoverage";

    /// <inheritdoc/>
    public ValueTask VerifyAsync(
        StartupVerificationContext context,
        IServiceProvider scopedServices,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(scopedServices);

        var authenticators = scopedServices.GetServices<IClientAuthenticator>().ToList();

        // Map method string → authenticator type name. Used to detect overlaps and uncovered methods.
        var declared = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var authenticator in authenticators)
        {
            var typeName = authenticator.GetType().Name;
            foreach (var method in authenticator.AuthenticationMethods)
                CheckDeclaredMethod(context, declared, typeName, method);
        }

        // Every server-advertised method (except none) must have a covering authenticator.
        var uncoveredMethods = _options.Value.TokenEndpoint.AuthMethodsSupported
            .Distinct(StringComparer.Ordinal)
            .Where(methodString => !string.Equals(methodString, TokenEndpointAuthMethods.None, StringComparison.Ordinal)
                && !declared.ContainsKey(methodString));

        foreach (var methodString in uncoveredMethods)
        {
            context.AddFailure(
                "authenticators.method_uncovered",
                $"TokenEndpoint.AuthMethodsSupported contains '{methodString}' but no registered " +
                "IClientAuthenticator covers it. Register an authenticator or remove the method.");
        }

        return ValueTask.CompletedTask;
    }

    private static void CheckDeclaredMethod(
        StartupVerificationContext context,
        Dictionary<string, string> declared,
        string typeName,
        string method)
    {
        // Reject leading/trailing whitespace before any other check: " none" or
        // "client_secret_basic " would pass the ordinal equality checks below but fail
        // silently at runtime because the runtime comparisons are also ordinal.
        if (method != method.Trim())
        {
            context.AddFailure(
                "authenticators.method_whitespace",
                $"{typeName} declares auth method '{method}' which has leading or trailing " +
                "whitespace. Method strings must match exactly — use the constants in " +
                $"{nameof(TokenEndpointAuthMethods)}.");
            return;
        }

        // Non-canonical casing (e.g. "Client_Secret_Basic") passes the ordinal overlap
        // check below but still collides at runtime with the built-in authenticator's
        // CanHandle, producing a silent invalid_client.
        if (_canonicalMethodNames.TryGetValue(method, out var canonical) &&
            !string.Equals(method, canonical, StringComparison.Ordinal))
        {
            context.AddFailure(
                "authenticators.method_casing",
                $"{typeName} declares auth method '{method}' which differs from the canonical " +
                $"form '{canonical}' in casing. Use the exact constant from " +
                $"{nameof(TokenEndpointAuthMethods)} to avoid silent runtime mismatches.");
            return;
        }

        if (string.Equals(method, TokenEndpointAuthMethods.None, StringComparison.Ordinal))
        {
            context.AddFailure(
                "authenticators.none_declared",
                $"{typeName} declares '{TokenEndpointAuthMethods.None}' in AuthenticationMethods. " +
                $"'{TokenEndpointAuthMethods.None}' is reserved for the CompositeClientAuthenticator " +
                "fallback and must not be declared by any IClientAuthenticator.");
            return;
        }

        if (declared.TryGetValue(method, out var existingType))
        {
            context.AddFailure(
                "authenticators.method_overlap",
                $"Both {existingType} and {typeName} declare auth method '{method}'. " +
                "Each method must be handled by exactly one IClientAuthenticator.");
        }
        else
        {
            declared[method] = typeName;
        }
    }

    // Case-insensitive map of framework-handled method strings to their canonical form.
    private static readonly IReadOnlyDictionary<string, string> _canonicalMethodNames =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [TokenEndpointAuthMethods.ClientSecretBasic] = TokenEndpointAuthMethods.ClientSecretBasic,
            [TokenEndpointAuthMethods.ClientSecretPost] = TokenEndpointAuthMethods.ClientSecretPost,
            [TokenEndpointAuthMethods.None] = TokenEndpointAuthMethods.None,
        };
}
