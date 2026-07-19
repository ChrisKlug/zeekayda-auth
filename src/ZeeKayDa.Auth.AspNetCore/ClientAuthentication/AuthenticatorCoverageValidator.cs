using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// Startup validator that ensures every method in <c>AuthMethodsSupported</c> is covered by
/// exactly one registered <see cref="IClientAuthenticator"/>, and that no authenticator
/// misconfigures the reserved <c>none</c> method or overlaps with another authenticator.
/// </summary>
internal sealed class AuthenticatorCoverageValidator : IValidateOptions<AuthorizationServerOptions>
{
    private readonly IServiceProvider _serviceProvider;

    public AuthenticatorCoverageValidator(IServiceProvider serviceProvider)
    {
        ArgumentNullException.ThrowIfNull(serviceProvider);
        _serviceProvider = serviceProvider;
    }

    public ValidateOptionsResult Validate(string? name, AuthorizationServerOptions options)
    {
        // Eagerly resolve authenticators so any DI construction error surfaces here.
        // If resolution fails (e.g., a dependency like IClientSecretHasher is missing),
        // skip this check — other validators will surface the root cause.
        IReadOnlyList<IClientAuthenticator> authenticators;
        try
        {
            authenticators = _serviceProvider.GetServices<IClientAuthenticator>().ToList();
        }
        catch (Exception)
        {
            return ValidateOptionsResult.Skip;
        }

        var errors = new List<string>();

        // Build the set of server-supported method strings once so both loops can use it.
        var serverMethods = new HashSet<string>(
            options.TokenEndpoint.AuthMethodsSupported,
            StringComparer.Ordinal);


        // Map method string → authenticator type name. Used to detect overlaps and uncovered methods.
        var declared = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var authenticator in authenticators)
        {
            var typeName = authenticator.GetType().Name;
            foreach (var method in authenticator.AuthenticationMethods)
            {
                // Reject leading/trailing whitespace before any other check: " none" or
                // "client_secret_basic " would pass the ordinal equality checks below but fail
                // silently at runtime because the runtime comparisons are also ordinal.
                if (method != method.Trim())
                {
                    errors.Add(
                        $"{typeName} declares auth method '{method}' which has leading or trailing " +
                        "whitespace. Method strings must match exactly — use the constants in " +
                        $"{nameof(TokenEndpointAuthMethods)}.");
                    continue;
                }

                // Reject non-canonical casing for well-known methods. A custom authenticator that
                // declares "Client_Secret_Basic" instead of "client_secret_basic" passes the ordinal
                // overlap check, but its CanHandle will still fire for the same requests as the
                // built-in authenticator, producing matches.Count > 1 and a silent invalid_client.
                if (_canonicalMethodNames.TryGetValue(method, out var canonical) &&
                    !string.Equals(method, canonical, StringComparison.Ordinal))
                {
                    errors.Add(
                        $"{typeName} declares auth method '{method}' which differs from the canonical " +
                        $"form '{canonical}' in casing. Use the exact constant from " +
                        $"{nameof(TokenEndpointAuthMethods)} to avoid silent runtime mismatches.");
                    continue;
                }

                if (string.Equals(method, TokenEndpointAuthMethods.None, StringComparison.Ordinal))
                {
                    errors.Add(
                        $"{typeName} declares '{TokenEndpointAuthMethods.None}' in AuthenticationMethods. " +
                        $"'{TokenEndpointAuthMethods.None}' is reserved for the CompositeClientAuthenticator " +
                        "fallback and must not be declared by any IClientAuthenticator.");
                    continue;
                }

                if (declared.TryGetValue(method, out var existingType))
                {
                    errors.Add(
                        $"Both {existingType} and {typeName} declare auth method '{method}'. " +
                        "Each method must be handled by exactly one IClientAuthenticator.");
                }
                else
                {
                    declared[method] = typeName;
                }
            }
        }

        // Every server-advertised method (except none) must have a covering authenticator.
        var nonNoneMethods = serverMethods.Where(
            methodString => !string.Equals(methodString, TokenEndpointAuthMethods.None, StringComparison.Ordinal));

        foreach (var methodString in nonNoneMethods)
        {
            if (!declared.ContainsKey(methodString))
            {
                errors.Add(
                    $"TokenEndpoint.AuthMethodsSupported contains '{methodString}' but no registered " +
                    "IClientAuthenticator covers it. Register an authenticator or remove the method.");
            }
        }

        return errors.Count > 0
            ? ValidateOptionsResult.Fail(errors)
            : ValidateOptionsResult.Success;
    }

    // Case-insensitive map of framework-handled method strings to their canonical form.
    // Guards against a custom authenticator declaring "Client_Secret_Basic" instead of
    // "client_secret_basic" — passes ordinal overlap checks but causes runtime mismatches.
    private static readonly IReadOnlyDictionary<string, string> _canonicalMethodNames =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            [TokenEndpointAuthMethods.ClientSecretBasic] = TokenEndpointAuthMethods.ClientSecretBasic,
            [TokenEndpointAuthMethods.ClientSecretPost] = TokenEndpointAuthMethods.ClientSecretPost,
            [TokenEndpointAuthMethods.None] = TokenEndpointAuthMethods.None,
        };
}
