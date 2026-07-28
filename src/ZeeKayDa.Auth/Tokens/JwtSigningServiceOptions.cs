namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Base options type for <see cref="JwtSigningService{TOptions}"/> implementations.
/// </summary>
/// <remarks>
/// Provider-specific options classes derive from one of the two tiers below —
/// <see cref="KeySetOptions"/> (Tier A) for a key source whose complete, fixed set of keys is
/// supplied at configuration time and never changes at runtime, or <see cref="KeySourceOptions"/>
/// (Tier B) for a key source the base class re-reads on a cadence because something else owns the
/// keys — never directly from this type. This base type deliberately carries no
/// acquisition-shaped property at all: every such knob lives on exactly one of the two tiers
/// (ADR 0015).
/// </remarks>
public abstract class JwtSigningServiceOptions
{
}
