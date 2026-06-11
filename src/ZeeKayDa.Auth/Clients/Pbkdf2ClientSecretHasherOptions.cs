namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Configuration options for <see cref="Pbkdf2ClientSecretHasher"/>.
/// </summary>
public sealed class Pbkdf2ClientSecretHasherOptions
{
    /// <summary>
    /// Default PBKDF2 iteration count (current OWASP PBKDF2-HMAC-SHA256 recommendation as of 2025).
    /// </summary>
    public const int DefaultIterations = 600_000;

    /// <summary>
    /// PBKDF2 iteration count used when creating new hashed secrets.
    /// </summary>
    /// <remarks>
    /// Must be at least <see cref="DefaultIterations"/> (600,000). Configuring a higher value
    /// strengthens brute-force resistance at the cost of increased CPU time per verification.
    /// Values above 2,000,000 are clamped with a startup warning; see
    /// <see cref="Pbkdf2ClientSecretHasher"/> for the rationale.
    /// </remarks>
    public int Iterations { get; set; } = DefaultIterations;
}
