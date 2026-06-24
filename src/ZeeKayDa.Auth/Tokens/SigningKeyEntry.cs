namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// A single key entry within a <see cref="SigningKeySet"/>, pairing a public
/// <see cref="SigningKeyDescriptor"/> with its position in the set.
/// </summary>
/// <param name="Descriptor">
/// The public key descriptor for this entry.
/// </param>
/// <param name="Index">
/// The zero-based index of this entry's private key in the owning <see cref="SigningKeySet"/>.
/// </param>
public sealed record SigningKeyEntry(SigningKeyDescriptor Descriptor, int Index);
