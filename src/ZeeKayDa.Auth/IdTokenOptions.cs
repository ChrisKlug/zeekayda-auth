namespace ZeeKayDa.Auth;

/// <summary>
/// ID token configuration options.
/// </summary>
public sealed class IdTokenOptions
{
    /// <summary>
    /// Gets or sets the ID token signing algorithms supported by this authorization server.
    /// Defaults to <c>[<see cref="SigningAlgorithm.RS256"/>]</c>.
    /// </summary>
    /// <remarks>
    /// Maps to the <c>id_token_signing_alg_values_supported</c> discovery metadata field.
    /// </remarks>
    public ICollection<SigningAlgorithm> SigningAlgValuesSupported { get; set; } = [SigningAlgorithm.RS256];
}
