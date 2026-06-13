using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// Authenticates clients using <c>client_secret_basic</c> (HTTP Basic authentication) or
/// <c>client_secret_post</c> (client secret in the request body).
/// </summary>
/// <remarks>
/// Delegates stored-secret verification to <see cref="CompositeClientSecretHasher"/> — never
/// compares secret strings directly. Tries all <see cref="IClientSecret"/> credentials before
/// returning a failure to support credential rotation (ADR 0007 §3.1).
/// </remarks>
internal sealed class ClientSecretAuthenticator : IClientAuthenticator
{
    private static readonly IReadOnlySet<string> _authMethods =
        new HashSet<string>(StringComparer.Ordinal)
        {
            TokenEndpointAuthMethods.ClientSecretBasic,
            TokenEndpointAuthMethods.ClientSecretPost,
        };

    private readonly CompositeClientSecretHasher _hasher;

    public ClientSecretAuthenticator(CompositeClientSecretHasher hasher)
    {
        ArgumentNullException.ThrowIfNull(hasher);
        _hasher = hasher;
    }

    /// <inheritdoc/>
    public IReadOnlySet<string> AuthenticationMethods => _authMethods;

    /// <inheritdoc/>
    /// <remarks>
    /// Returns <see langword="true"/> with <c>client_secret_basic</c> when an
    /// <c>Authorization: Basic</c> header is present — including the case where a
    /// simultaneous <c>client_secret</c> form field is present, which
    /// <see cref="AuthenticateAsync"/> rejects. Returns <see langword="true"/> with
    /// <c>client_secret_post</c> when only a <c>client_secret</c> form field is present.
    /// Returns <see langword="false"/> when neither is present.
    /// </remarks>
    public bool CanHandle(TokenRequestContext context, out string? method)
    {
        ArgumentNullException.ThrowIfNull(context);

        var hasBasic = HasBasicAuthHeader(context.Headers);
        var hasPost = context.Form.ContainsKey("client_secret");

        if (hasBasic)
        {
            method = TokenEndpointAuthMethods.ClientSecretBasic;
            return true;
        }

        if (hasPost)
        {
            method = TokenEndpointAuthMethods.ClientSecretPost;
            return true;
        }

        method = null;
        return false;
    }

    /// <inheritdoc/>
    public ValueTask<ClientAuthenticationResult> AuthenticateAsync(
        ClientAuthenticationContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var hasBasic = HasBasicAuthHeader(context.Headers);
        var hasPost = context.Form.ContainsKey("client_secret");

        // RFC 6749 §2.3: a client MUST NOT use more than one authentication method per request.
        if (hasBasic && hasPost)
        {
            _hasher.PadFailureToCredentialBudget(0);
            return ValueTask.FromResult(ClientAuthenticationResult.NotValid());
        }

        string presented;
        if (hasBasic)
        {
            // RFC 6749 §2.3.1: the Basic-auth username is the authoritative client_id.
            if (!TryParseBasicCredentials(context.Headers, out var username, out var password) ||
                !string.Equals(username, context.ClientId, StringComparison.Ordinal))
            {
                _hasher.PadFailureToCredentialBudget(0);
                return ValueTask.FromResult(ClientAuthenticationResult.NotValid());
            }

            // If the form body also carries a client_id it must agree with the Basic-auth
            // username — two conflicting client_id values in one request is a protocol error
            // regardless of which one the caller used to look up the client.
            var formClientId = context.Form["client_id"].ToString();
            if (formClientId.Length > 0 &&
                !string.Equals(formClientId, username, StringComparison.Ordinal))
            {
                _hasher.PadFailureToCredentialBudget(0);
                return ValueTask.FromResult(ClientAuthenticationResult.NotValid());
            }

            presented = password;
        }
        else
        {
            presented = context.Form["client_secret"].ToString();
        }

        var secrets = context.Client.Credentials.OfType<IClientSecret>().ToList();

        if (secrets.Count == 0)
        {
            _hasher.PadFailureToCredentialBudget(0);
            return ValueTask.FromResult(ClientAuthenticationResult.NotValid());
        }

        var attempted = 0;
        foreach (var stored in secrets)
        {
            attempted++;
            if (_hasher.Verify(stored, presented.AsSpan()))
                return ValueTask.FromResult(ClientAuthenticationResult.Valid());
        }

        // Pad timing to the credential budget so a client with fewer active secrets is not
        // distinguishable from one with the maximum by timing (ADR 0007 §3.4).
        _hasher.PadFailureToCredentialBudget(attempted);
        return ValueTask.FromResult(ClientAuthenticationResult.NotValid());
    }

    private static bool HasBasicAuthHeader(IHeaderDictionary headers)
    {
        var authHeader = headers.Authorization;
        return authHeader.Count == 1 &&
               authHeader[0] is { } value &&
               value.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Parses and form-URL-decodes the username and password from an <c>Authorization: Basic</c>
    /// header per RFC 6749 §2.3.1. Returns <see langword="false"/> on malformed input.
    /// </summary>
    private static bool TryParseBasicCredentials(
        IHeaderDictionary headers,
        out string username,
        out string password)
    {
        username = string.Empty;
        password = string.Empty;
        var authHeader = headers.Authorization[0]!;
        var base64Part = authHeader["Basic ".Length..].Trim();
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(base64Part));
            var colonIndex = decoded.IndexOf(':');
            if (colonIndex < 0) return false;

            // RFC 6749 §2.3.1 requires application/x-www-form-urlencoded encoding of both
            // values before they are base64-encoded into the Basic header.
            username = WebUtility.UrlDecode(decoded[..colonIndex]);
            password = WebUtility.UrlDecode(decoded[(colonIndex + 1)..]);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
