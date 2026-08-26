using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Options;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.AspNetCore.Endpoints;

/// <summary>
/// Registers the JWKS endpoint (<c>connect/jwks</c> by default) serving the signing key ring's
/// published keys as an RFC 7517 JWK Set.
/// </summary>
/// <remarks>
/// The response body is derived lazily from <see cref="ISigningKeyRing.Current"/> and reused for
/// as long as the ring returns the same <see cref="SigningKeySet"/> instance, checked by reference
/// on every request. No observer wiring: under the read-once ring the set never changes for the
/// process lifetime, and a ring that swaps its set at runtime is picked up on the next request
/// simply because the reference differs.
/// </remarks>
internal sealed class JwksEndpoint : IZeeKayDaEndpoint
{
    private readonly IOptions<AuthorizationServerOptions> _options;
    private readonly HashSet<string> _allowedOrigins;

    private volatile CachedResponse? _cached;

    /// <summary>The serialized body, and the key set instance it was derived from.</summary>
    private sealed record CachedResponse(SigningKeySet KeySet, byte[] Body);

    public JwksEndpoint(IOptions<AuthorizationServerOptions> options)
    {
        _options = options;
        // Config values are already validated and canonicalized to lowercase by startup validation.
        _allowedOrigins = new HashSet<string>(
            options.Value.JwksEndpoint.CorsOrigins,
            StringComparer.OrdinalIgnoreCase);
    }

    /// <inheritdoc/>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        var issuerUri = EndpointRouteHelper.GetIssuerUri(_options);
        var endpointUri = EndpointRouteHelper.GetPublishedEndpointUri(
            issuerUri,
            _options.Value.JwksEndpoint.Uri,
            "connect/jwks");

        // AllowAnonymous so a host-wide authorization fallback policy cannot turn the JWKS into a
        // 401 — the key set must stay publicly readable or every relying party's validation stops.
        endpoints.MapGet(endpointUri.AbsolutePath, Handle)
            .RequireIssuerHost(endpointUri)
            .AllowAnonymous();
    }

    // The ring is a handler parameter, not a constructor dependency: endpoint instances are
    // constructed while the host is still being built, and resolving the ring constructs the
    // signing key source — work that must not happen before the cheap startup checks have passed.
    // [FromServices] because the ring is conditionally registered: without it, a host with no
    // signing source would fail at route mapping with a body-inference error instead of reaching
    // the startup check that names the actual problem.
    private IResult Handle([FromServices] ISigningKeyRing ring, HttpContext context)
    {
        PublicMetadataHeaders.Apply(
            context, _options.Value.JwksEndpoint.CacheMaxAge, _allowedOrigins);

        // The ring is initialized at startup or the host never started, so Current cannot throw
        // here; the reference check makes concurrent requests race only towards writing the same
        // bytes.
        var keySet = ring.Current;
        var cached = _cached;
        if (cached is null || !ReferenceEquals(cached.KeySet, keySet))
        {
            cached = new CachedResponse(keySet, JwkSetWriter.Write(keySet.Published));
            _cached = cached;
        }

        return Results.Bytes(cached.Body, "application/jwk-set+json");
    }
}
