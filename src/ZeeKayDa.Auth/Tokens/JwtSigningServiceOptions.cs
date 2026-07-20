namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Base options type for <see cref="JwtSigningService{TOptions}"/> implementations.
/// </summary>
/// <remarks>
/// <para>
/// Provider-specific options classes derive from one of the two tiers below —
/// <see cref="StaticKeySourceOptions"/> for a key source that is immutable for the process
/// lifetime, or <see cref="RotatingKeySourceOptions"/> for a key source that can change while the
/// process runs — never directly from this type. This base type deliberately carries no
/// rotation-shaped property at all: every rotation-related knob lives on exactly one of the two
/// tiers (ADR 0011 §3.4, issue #409).
/// </para>
/// <para>
/// This three-tier hierarchy replaces an earlier design in which this type carried a single
/// nullable <c>KeySourceRefreshInterval</c> property, with <see langword="null"/> as a sentinel
/// for "static, load-once" mode. That sentinel is now a real type distinction: which tier a
/// provider's options type derives from determines whether <c>LoadKeysAsync</c> is invoked once,
/// ever, or on a recurring poll cadence.
/// </para>
/// </remarks>
public abstract class JwtSigningServiceOptions
{
}
