namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// A hashed client secret, stored as one self-describing string.
/// </summary>
/// <param name="Value">
/// The hash in the form <c>$&lt;algorithm id&gt;$...</c>, for example
/// <c>$pbkdf2-sha256$i=600000$&lt;salt&gt;$&lt;hash&gt;</c>. The framework reads only the algorithm id,
/// to pick the <see cref="IClientSecretHasher"/> that declared it; the rest belongs to that hasher.
/// </param>
/// <remarks>
/// <para>
/// Any store can persist any hasher's output, because it is a string. A store does not need to
/// know which hashing algorithm produced it.
/// </para>
/// <para>
/// Create one with <see cref="ClientSecrets"/>, which hashes with the host's default hasher.
/// A hash produced elsewhere — by another system's PHC-format library, for example — can be stored
/// as it is, as long as a registered hasher declares its algorithm id.
/// </para>
/// </remarks>
public sealed record ClientSecret(string Value)
{
    /// <summary>
    /// Returns the type name only. A plaintext secret pasted into a store where a hash belongs
    /// would otherwise reach any log that prints a registration.
    /// </summary>
    public override string ToString() => nameof(ClientSecret);
}
