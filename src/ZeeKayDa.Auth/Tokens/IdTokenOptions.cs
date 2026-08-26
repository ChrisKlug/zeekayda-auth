namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// ID token configuration options.
/// </summary>
public sealed class IdTokenOptions
{
    /// <summary>
    /// Gets or sets an optional narrowing filter on the ID token signing algorithms this
    /// authorization server advertises. <see langword="null"/> — the default — advertises every
    /// algorithm in the published signing key set.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The advertised set is derived from <see cref="SigningKeySet.AdvertisedAlgorithms"/>, so this
    /// filter can only withhold an algorithm the server could otherwise advertise; it can never add
    /// one the key set cannot produce. Naming an algorithm that is not in the published set is a
    /// no-op and warns at startup.
    /// </para>
    /// <para>
    /// A filter that excludes <see cref="SigningKeySet.SigningKey"/>'s own algorithm fails startup:
    /// it would advertise nothing the server actually signs with.
    /// </para>
    /// <para>
    /// Maps to the <c>id_token_signing_alg_values_supported</c> discovery metadata field.
    /// </para>
    /// </remarks>
    public ICollection<SigningAlgorithm>? AdvertisedSigningAlgorithms { get; set; }
}
