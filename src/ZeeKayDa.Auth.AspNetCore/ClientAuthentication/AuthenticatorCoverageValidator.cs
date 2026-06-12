using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Clients;

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
        IEnumerable<IClientAuthenticator> authenticators;
        try
        {
            authenticators = _serviceProvider.GetServices<IClientAuthenticator>();
        }
        catch (Exception ex)
        {
            return ValidateOptionsResult.Fail(
                $"Failed to resolve IClientAuthenticator registrations: {ex.Message}");
        }

        var errors = new List<string>();

        // Map method string → authenticator type name. Used to detect overlaps and uncovered methods.
        var declared = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var authenticator in authenticators)
        {
            var typeName = authenticator.GetType().Name;
            foreach (var method in authenticator.AuthenticationMethods)
            {
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

        foreach (var enumMethod in options.TokenEndpoint.AuthMethodsSupported)
        {
            string methodString;
            try
            {
                methodString = ToMethodString(enumMethod);
            }
            catch (ArgumentOutOfRangeException)
            {
                errors.Add(
                    $"TokenEndpoint.AuthMethodsSupported contains '{enumMethod}', which has no " +
                    "supported string mapping. Remove it or add a corresponding IClientAuthenticator.");
                continue;
            }

            // none is always covered by the composite fallback — no authenticator needed.
            if (string.Equals(methodString, TokenEndpointAuthMethods.None, StringComparison.Ordinal))
                continue;

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

    // NOTE: duplicates CompositeClientAuthenticator.ToMethodString intentionally — both bridge
    // the same enum→string gap and both go away when AuthMethodsSupported becomes ICollection<string>
    // (ADR 0007 §1a amendment follow-up).
    private static string ToMethodString(TokenEndpointAuthMethod method) => method switch
    {
        TokenEndpointAuthMethod.ClientSecretBasic => TokenEndpointAuthMethods.ClientSecretBasic,
        TokenEndpointAuthMethod.ClientSecretPost => TokenEndpointAuthMethods.ClientSecretPost,
        TokenEndpointAuthMethod.None => TokenEndpointAuthMethods.None,
        _ => throw new ArgumentOutOfRangeException(nameof(method), method, null),
    };
}
