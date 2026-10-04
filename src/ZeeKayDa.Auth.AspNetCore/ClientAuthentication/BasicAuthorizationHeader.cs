using System.Net;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace ZeeKayDa.Auth.AspNetCore.ClientAuthentication;

/// <summary>
/// The <c>Authorization: Basic</c> header as RFC 6749 §2.3.1 shapes it for a client: both halves
/// form-encoded before the pair is base64-encoded.
/// </summary>
internal static class BasicAuthorizationHeader
{
    private const string Scheme = "Basic ";

    /// <summary>
    /// Whether the request carries exactly one <c>Authorization</c> header, and it is Basic: a bare
    /// <c>Basic</c> with no credentials is still a Basic credential, malformed (RFC 7617 §2).
    /// </summary>
    public static bool IsPresent(IHeaderDictionary headers)
    {
        var authHeader = headers.Authorization;
        return authHeader.Count == 1 &&
               authHeader[0] is { } value &&
               (value.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase) ||
                value.Trim().Equals(Scheme.TrimEnd(), StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// The password the header presents for <paramref name="clientId"/>, or <see langword="null"/>
    /// when the header cannot be decoded, names another client (RFC 6749 §2.3.1: its username is the
    /// authoritative <c>client_id</c>), or disagrees with a <c>client_id</c> in the form. Only
    /// meaningful after <see cref="IsPresent"/>.
    /// </summary>
    public static string? SecretFor(IHeaderDictionary headers, string clientId, IFormCollection form)
    {
        if (!TryParse(headers, out var username, out var password) ||
            !string.Equals(username, clientId, StringComparison.Ordinal))
            return null;

        // Two conflicting client_id values in one request is a protocol error, whichever one the
        // caller used to look up the client.
        var formClientId = form["client_id"].ToString();
        return formClientId.Length > 0 && !string.Equals(formClientId, username, StringComparison.Ordinal)
            ? null
            : password;
    }

    /// <summary>
    /// Decodes the header's credentials. Only meaningful after <see cref="IsPresent"/>; a header
    /// that is not valid base64 or carries no colon yields <see langword="false"/>.
    /// </summary>
    public static bool TryParse(IHeaderDictionary headers, out string username, out string password)
    {
        username = string.Empty;
        password = string.Empty;
        var authHeader = headers.Authorization[0]!;
        var base64Part = authHeader.Length > Scheme.Length ? authHeader[Scheme.Length..].Trim() : string.Empty;
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(base64Part));
            var colonIndex = decoded.IndexOf(':');
            if (colonIndex < 0) return false;

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
