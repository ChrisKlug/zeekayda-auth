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
    /// Must be between 600,000 and 2,000,000; startup fails otherwise. Configuring a higher value
    /// strengthens brute-force resistance at the cost of increased CPU time per verification. Set it
    /// with <c>services.Configure&lt;Pbkdf2ClientSecretHasherOptions&gt;(…)</c> or bind it from
    /// configuration.
    /// </remarks>
    public int Iterations { get; set; } = DefaultIterations;
}
