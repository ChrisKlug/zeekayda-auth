using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Configuration;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// The canonical form of <see cref="AuthorizationServerOptions.CorsOrigins"/>, built once from the
/// host's validated configuration for the endpoints that match a request's <c>Origin</c>.
/// </summary>
/// <remarks>
/// The options keep the host's entries exactly as configured; the canonical set is derived here,
/// where it is used. Startup validation has already refused any entry with no canonical form.
/// </remarks>
internal sealed class CorsAllowlist(IOptions<AuthorizationServerOptions> options)
{
    private readonly HashSet<string> _origins = new(
        options.Value.CorsOrigins.Select(CorsOrigin.Canonicalize),
        StringComparer.OrdinalIgnoreCase);

    /// <summary>Whether no origin is listed, which allows every origin.</summary>
    public bool IsEmpty => _origins.Count == 0;

    /// <summary>
    /// Finds the listed origin matching <paramref name="requestOrigin"/>, case-insensitively,
    /// and returns the listed canonical form, never the request's own spelling.
    /// </summary>
    public bool TryMatch(string requestOrigin, [MaybeNullWhen(false)] out string allowedOrigin) =>
        _origins.TryGetValue(requestOrigin, out allowedOrigin);
}
