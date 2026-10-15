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
    /// Between 600,000 and 2,000,000, or startup fails; higher costs more CPU per verification. Read once at
    /// startup, so a configuration reload does not change it.
    /// </remarks>
    public int Iterations { get; set; } = DefaultIterations;
}
