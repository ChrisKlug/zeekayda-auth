namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// The claims a token is issued over, already selected and finalized by the caller.
/// </summary>
/// <param name="Claims">
/// The claims, keyed by claim name exactly as they must appear in the token. The issuer performs
/// no selection, renaming, or enrichment — claim selection is the caller's job, done before this
/// type is constructed.
/// </param>
/// <remarks>
/// Deliberately claims rather than serialized bytes: a JWT issuer serializes them to JSON, but an
/// opaque issuer wants claims to hand to a store, and a payload that arrived pre-serialized would
/// force it to deserialize what the caller just serialized. This is what keeps
/// <see cref="ITokenIssuer"/> implementable with no reference to any JWS-specific type.
/// </remarks>
public sealed record TokenPayload(IReadOnlyDictionary<string, object?> Claims);
