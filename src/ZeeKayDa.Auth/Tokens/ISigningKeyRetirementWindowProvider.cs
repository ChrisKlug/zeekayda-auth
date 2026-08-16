namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// Computes how long a signing key that is no longer the active signer remains published in the
/// JWKS (and therefore trusted by relying parties).
/// </summary>
public interface ISigningKeyRetirementWindowProvider
{
    /// <summary>
    /// Gets the retirement window: how long a superseded signing key must remain published and
    /// trusted after it stops being the active signer.
    /// </summary>
    /// <returns>The retirement window.</returns>
    TimeSpan GetRetirementWindow();
}
