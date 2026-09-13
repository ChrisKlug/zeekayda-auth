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

    /// <summary>Whether the request carries exactly one <c>Authorization</c> header, and it is Basic.</summary>
    public static bool IsPresent(IHeaderDictionary headers)
    {
        var authHeader = headers.Authorization;
        return authHeader.Count == 1 &&
               authHeader[0] is { } value &&
               value.StartsWith(Scheme, StringComparison.OrdinalIgnoreCase);
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
        var base64Part = authHeader[Scheme.Length..].Trim();
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
