using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// The <c>zkd_i</c> query parameter naming the interaction, written onto every redirect to a host
/// page and read back when the page completes it.
/// </summary>
/// <remarks>
/// Without it a sign-in would complete whatever interaction the browser carries — one planted by
/// an attacker's authorization request, or another tab's.
/// </remarks>
internal static class InteractionHandoff
{
    /// <summary>The query parameter carrying the interaction identifier: an identifier, never a URL.</summary>
    public const string InteractionIdParameter = "zkd_i";

    /// <summary>Builds the redirect to a host interaction page for the given interaction.</summary>
    public static string BuildRedirectUrl(string path, string interactionId) =>
        QueryHelpers.AddQueryString(path, InteractionIdParameter, interactionId);

    /// <summary>
    /// The interaction identifier from the query string, else from a posted form field;
    /// <see langword="null"/> when absent, empty, or supplied more than once.
    /// </summary>
    public static async ValueTask<string?> ReadInteractionIdAsync(HttpRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (Single(request.Query[InteractionIdParameter]) is { } fromQuery)
            return fromQuery;

        if (!request.HasFormContentType)
            return null;

        var form = await request.ReadFormAsync(request.HttpContext.RequestAborted).ConfigureAwait(false);
        return Single(form[InteractionIdParameter]);
    }

    /// <summary>Compares two interaction identifiers in fixed time: the identifier is never published.</summary>
    public static bool IdentifiersMatch(string expected, string supplied)
    {
        ArgumentNullException.ThrowIfNull(expected);
        ArgumentNullException.ThrowIfNull(supplied);

        // No allocation for a request value of any length; the length is not a secret.
        return CryptographicOperations.FixedTimeEquals(
            MemoryMarshal.AsBytes(expected.AsSpan()),
            MemoryMarshal.AsBytes(supplied.AsSpan()));
    }

    /// <summary>Refuses a duplicated parameter, as the authorization endpoint does: an attacker must not pick.</summary>
    private static string? Single(Microsoft.Extensions.Primitives.StringValues values) =>
        values.Count == 1 && !string.IsNullOrEmpty(values[0]) ? values[0] : null;
}
