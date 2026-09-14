using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Matching;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// Marks a framework endpoint whose request path must equal its route template exactly.
/// </summary>
internal sealed class ExactPathMetadata
{
    public static readonly ExactPathMetadata Instance = new();

    private ExactPathMetadata()
    {
    }
}

/// <summary>
/// Takes an endpoint carrying <see cref="ExactPathMetadata"/> out of route matching unless the
/// request path equals its route template ordinally.
/// </summary>
/// <remarks>
/// Routing matches literal segments case-insensitively and tolerates a trailing <c>/</c>, but a URL
/// path is case-sensitive (RFC 3986 §6.2.2.1): <c>/TENANT1/connect/token</c> is not this issuer's
/// endpoint. Deciding it while the route is still being chosen — ahead of the HTTP-method policy —
/// makes a wrong path "no route", so it is a 404 whatever the method, and never reaches the
/// framework's HTTPS or header filters. Endpoints without the marker are untouched.
/// </remarks>
internal sealed class ExactPathMatcherPolicy : MatcherPolicy, INodeBuilderPolicy
{
    // Ahead of HttpMethodMatcherPolicy, so a wrong path is never reported as a wrong method (405).
    public override int Order => -2000;

    public bool AppliesToEndpoints(IReadOnlyList<Endpoint> endpoints)
        => endpoints.Any(IsExactPathEndpoint);

    public IReadOnlyList<PolicyNodeEdge> GetEdges(IReadOnlyList<Endpoint> endpoints)
    {
        // An unmarked endpoint matches on every edge; a marked one only on its own exact path.
        var unmarked = endpoints.Where(endpoint => !IsExactPathEndpoint(endpoint)).ToList();

        var edges = endpoints
            .Where(IsExactPathEndpoint)
            .GroupBy(endpoint => ExactPathOf((RouteEndpoint)endpoint), StringComparer.Ordinal)
            .Select(group => new PolicyNodeEdge(new ExactPath(group.Key), [.. group, .. unmarked]))
            .ToList();

        if (unmarked.Count > 0)
            edges.Add(new PolicyNodeEdge(ExactPath.Any, unmarked));

        return edges;
    }

    public PolicyJumpTable BuildJumpTable(int exitDestination, IReadOnlyList<PolicyJumpTableEdge> edges)
    {
        var destinations = new Dictionary<string, int>(StringComparer.Ordinal);
        var anyDestination = exitDestination;

        foreach (var edge in edges)
        {
            if (((ExactPath)edge.State).Value is { } path)
                destinations[path] = edge.Destination;
            else
                anyDestination = edge.Destination;
        }

        return new ExactPathJumpTable(destinations, anyDestination);
    }

    /// <summary>
    /// The literal path a marked endpoint answers. A template with a parameter has no single exact
    /// path, and one without raw text has nothing to compare against — either would silently
    /// match nothing or everything, so the matcher refuses to build instead.
    /// </summary>
    internal static string ExactPathOf(RouteEndpoint endpoint)
    {
        var pattern = endpoint.RoutePattern;
        if (pattern.RawText is not { } rawText || pattern.Parameters.Count > 0)
        {
            throw new InvalidOperationException(
                $"Endpoint '{endpoint.DisplayName}' is marked for exact-path matching but its route " +
                $"'{pattern.RawText ?? "<no raw text>"}' is not a literal path. Framework routes must be literal paths.");
        }

        return rawText;
    }

    private static bool IsExactPathEndpoint(Endpoint endpoint)
        => endpoint is RouteEndpoint && endpoint.Metadata.GetMetadata<ExactPathMetadata>() is not null;

    private sealed record ExactPath(string? Value)
    {
        public static readonly ExactPath Any = new((string?)null);
    }

    private sealed class ExactPathJumpTable(Dictionary<string, int> destinations, int anyDestination) : PolicyJumpTable
    {
        public override int GetDestination(HttpContext httpContext)
            => destinations.TryGetValue(httpContext.Request.Path.ToUriComponent(), out var destination)
                ? destination
                : anyDestination;
    }
}
