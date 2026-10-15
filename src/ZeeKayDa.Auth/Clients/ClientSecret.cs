namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// A hashed client secret, stored as one self-describing string.
/// </summary>
/// <param name="Value">
/// The hash as <c>$&lt;algorithm id&gt;$...</c>, such as <c>$pbkdf2-sha256$i=600000$&lt;salt&gt;$&lt;hash&gt;</c>;
/// the framework reads only the id, and the rest belongs to the hasher declaring it.
/// </param>
/// <remarks>
/// A string, so any store can persist any hasher's output. Create one with <see cref="ClientSecrets"/>, or
/// store a hash made elsewhere as long as a registered hasher declares its algorithm id.
/// </remarks>
public sealed record ClientSecret(string Value)
{
    /// <summary>
    /// Returns the type name only. A plaintext secret pasted into a store where a hash belongs
    /// would otherwise reach any log that prints a registration.
    /// </summary>
    public override string ToString() => nameof(ClientSecret);
}
