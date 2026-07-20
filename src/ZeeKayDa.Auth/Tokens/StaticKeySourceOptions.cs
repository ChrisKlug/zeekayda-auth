namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Base options type for a <see cref="JwtSigningService{TOptions}"/> provider whose key source is
/// immutable for the lifetime of the process.
/// </summary>
/// <remarks>
/// This tier carries no refresh-cadence property. Deriving from this type tells the base class
/// that the key source never changes, so <c>LoadKeysAsync</c> is called at most once for the
/// lifetime of the service and the cached <see cref="SigningKeySet"/> is never invalidated or
/// disposed while the service is live (ADR 0011 §3.4). <see cref="DevelopmentSigningKeyOptions"/>
/// is currently the sole consumer of this tier: a locally-generated or file-persisted development
/// key set never changes at runtime, so there is nothing to poll.
/// </remarks>
public abstract class StaticKeySourceOptions : JwtSigningServiceOptions
{
}
