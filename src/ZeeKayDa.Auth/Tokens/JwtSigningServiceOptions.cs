namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Base options type for <see cref="JwtSigningService{TOptions}"/> implementations.
/// </summary>
/// <remarks>
/// Provider-specific options classes derive from <see cref="KeySetOptions"/> (a complete, fixed
/// key set supplied at configuration time) or <see cref="KeySourceOptions"/> (a key source the base
/// class re-reads on a cadence because something else owns the keys) — never directly from this
/// type. This base type deliberately carries no acquisition-shaped property at all: every such knob
/// lives on exactly one of the two option types.
/// </remarks>
public abstract class JwtSigningServiceOptions
{
}
