namespace ZeeKayDa.Auth.MacOS;

/// <summary>
/// A single Keychain label registered with <see cref="MacOsKeychainSigningOptions"/>, together with
/// an optional explicit activation window.
/// </summary>
/// <param name="Label">The Keychain item's label.</param>
/// <param name="ActivatesAt">
/// The explicit activation time given via <see cref="MacOsKeychainSigningOptions.AddKey(string, DateTimeOffset, DateTimeOffset?)"/>,
/// or <see langword="null"/> when this label was registered via
/// <see cref="MacOsKeychainSigningOptions.AddKey(string)"/> (or as the primary label): the label's
/// shape is auto-detected at load time — a certificate anchors on its own <c>NotBefore</c>/<c>NotAfter</c>;
/// a bare key with no explicit activation has none, which is only valid when it is the sole registered
/// key (the bootstrap exemption).
/// </param>
/// <param name="ExpiresAt">The explicit expiry given alongside <see cref="ActivatesAt"/>, if any.</param>
public readonly record struct RegisteredKeyLabel(string Label, DateTimeOffset? ActivatesAt, DateTimeOffset? ExpiresAt);
