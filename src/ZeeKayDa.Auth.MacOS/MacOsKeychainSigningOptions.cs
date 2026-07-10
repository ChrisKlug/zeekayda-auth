using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.MacOS;

/// <summary>
/// Configuration options for <c>AddMacOsKeychainSigning</c>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="JwtSigningServiceOptions.RefreshInterval"/> is inherited from the base class and
/// defaults to 5 minutes. As with the Windows Certificate Store provider, this value does not gate a
/// re-download of private key material — every registered label is re-resolved against the Keychain
/// on every refresh — and instead doubles as the threshold used to warn when a rotated-in key's
/// activation is scheduled too soon relative to how often relying parties are expected to have
/// polled the JWKS (see <see cref="SigningKeyRotation.HasTooSoonPendingActivation"/>).
/// </para>
/// <para>
/// Each registered label is either certificate-backed or a bare, certificate-less key; the shape is
/// auto-detected at load time from what is actually present in the Keychain — see
/// <see cref="AddKey(string)"/> and <see cref="AddKey(string, DateTimeOffset, DateTimeOffset?)"/>.
/// </para>
/// </remarks>
public sealed class MacOsKeychainSigningOptions : JwtSigningServiceOptions
{
    private readonly List<RegisteredKeyLabel> _additionalKeys = [];

    /// <summary>
    /// Gets or sets the label of the required/primary Keychain item. Set by
    /// <c>AddMacOsKeychainSigning</c>. Its shape (certificate-backed, or a bare key) is auto-detected
    /// at load time, exactly as for a label added via <see cref="AddKey(string)"/> — including no
    /// explicit activation time, which is only valid while this ends up being the sole registered
    /// key. There is no way to give the primary label an explicit activation time: a bare key that
    /// will participate in a 2-or-more-key rotation must always be registered via
    /// <see cref="AddKey(string, DateTimeOffset, DateTimeOffset?)"/> instead — never as the primary
    /// label — so a rotation involving a bare key requires either a certificate-backed primary label
    /// (anchoring on its own <c>NotBefore</c>/<c>NotAfter</c>) or restructuring which item is primary.
    /// </summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the JWS algorithm to use when signing. A Keychain key does not itself declare
    /// RS256 vs PS256 — that choice is made here and must match the key's actual type (RSA algorithms
    /// for RSA keys, EC algorithms for EC keys). Defaults to RS256.
    /// </summary>
    public SigningAlgorithm Algorithm { get; set; } = SigningAlgorithm.RS256;

    /// <summary>
    /// Gets every additional key registered via <see cref="AddKey(string)"/> or
    /// <see cref="AddKey(string, DateTimeOffset, DateTimeOffset?)"/>, in registration order.
    /// </summary>
    public IReadOnlyList<RegisteredKeyLabel> AdditionalKeys => _additionalKeys;

    /// <summary>
    /// Registers an additional Keychain label to support rotation with overlapping validity windows
    /// (ADR 0011 §3.5; issue #282's multi-key registration shape), with no explicit activation time.
    /// </summary>
    /// <remarks>
    /// <para>
    /// At load time, this label's shape is auto-detected: if a certificate with this label exists in
    /// the Keychain, it anchors on the certificate's own <c>NotBefore</c>/<c>NotAfter</c>, exactly
    /// like the Windows Certificate Store provider. If instead only a bare (certificate-less) key
    /// exists with this label, it has no explicit activation time — which is only valid when it ends
    /// up being the <em>sole</em> registered key (the single-key bootstrap exemption already applies
    /// to bare keys the same way it applies to certificates). If 2 or more keys are registered in
    /// total and this label resolves to a bare key with no explicit activation, startup fails fast
    /// with a clear exception naming this label and pointing at
    /// <see cref="AddKey(string, DateTimeOffset, DateTimeOffset?)"/> instead.
    /// </para>
    /// <para>
    /// Use <see cref="AddKey(string, DateTimeOffset, DateTimeOffset?)"/> directly for a bare key that
    /// will participate in rotation, to give it an explicit, unambiguous activation time.
    /// </para>
    /// </remarks>
    /// <param name="label">The additional Keychain item's label.</param>
    /// <returns>This instance, so calls can be chained.</returns>
    public MacOsKeychainSigningOptions AddKey(string label)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(label);
        _additionalKeys.Add(new RegisteredKeyLabel(label, ActivatesAt: null, ExpiresAt: null));
        return this;
    }

    /// <summary>
    /// Registers an additional, bare (certificate-less) Keychain key with an explicit activation
    /// window, to support rotation with overlapping validity windows.
    /// </summary>
    /// <param name="label">The additional Keychain item's label.</param>
    /// <param name="activatesAt">
    /// The instant this key becomes eligible to be the active signer. Required: a bare key has no
    /// certificate <c>NotBefore</c> to anchor on. Ignored (per the single-key bootstrap exemption) if
    /// this ends up being the sole registered key.
    /// </param>
    /// <param name="expiresAt">
    /// The instant this key stops being eligible to sign or be trusted. Optional — when omitted, the
    /// key never expires (the 30-day-expiry warning simply never fires for it).
    /// </param>
    /// <returns>This instance, so calls can be chained.</returns>
    public MacOsKeychainSigningOptions AddKey(string label, DateTimeOffset activatesAt, DateTimeOffset? expiresAt = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(label);
        _additionalKeys.Add(new RegisteredKeyLabel(label, activatesAt, expiresAt));
        return this;
    }
}
