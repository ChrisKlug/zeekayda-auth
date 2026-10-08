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
/// The response body is derived lazily from <see cref="SigningKeyRing.Current"/> and reused for
/// as long as the ring returns the same <see cref="SigningKeySet"/> instance, checked by reference
/// on every request. No observer wiring: when the ring swaps its set at a key change, the next
/// request picks it up simply because the reference differs.
/// </remarks>
internal sealed class JwksEndpoint(IOptions<AuthorizationServerOptions> options, CorsAllowlist allowedOrigins) : IZeeKayDaEndpoint
{

    private volatile CachedResponse? _cached;

    /// <summary>The serialized body, and the key set instance it was derived from.</summary>
    private sealed record CachedResponse(SigningKeySet KeySet, byte[] Body);

    /// <inheritdoc/>
    public void Map(IEndpointRouteBuilder endpoints)
    {
        var issuerUri = EndpointRouteHelper.GetIssuerUri(options);
        var endpointUri = EndpointRouteHelper.GetPublishedEndpointUri(
            issuerUri,
            options.Value.JwksEndpoint.Uri,
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
    internal IResult Handle([FromServices] SigningKeyRing ring, HttpContext context)
    {
        // The ring is initialized at startup or the host never started, so Current cannot throw
        // here; the reference check makes concurrent requests race only towards writing the same
        // bytes.
        var keySet = ring.Current;

        // An empty set means signing has stopped; a relying party caching it would reject the
        // resumed key's tokens for the whole cache lifetime.
        PublicMetadataHeaders.Apply(
            context, keySet.Published.Count == 0 ? TimeSpan.Zero : options.Value.JwksEndpoint.CacheMaxAge, allowedOrigins);

        var cached = _cached;
        if (cached is null || !ReferenceEquals(cached.KeySet, keySet))
        {
            cached = new CachedResponse(keySet, JwkSetWriter.Write(keySet.Published));
            _cached = cached;
        }

        return Results.Bytes(cached.Body, "application/jwk-set+json");
    }
}
