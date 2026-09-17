namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// A PBKDF2-hashed client secret.
/// </summary>
/// <remarks>
/// The C# type identity is the hashing algorithm — no string discriminator is needed.
/// A consumer adding a different hashing algorithm (for example bcrypt) defines a new
/// sub-interface of <see cref="IClientSecret"/> and pairs it with a matching hasher.
/// </remarks>
public interface IPbkdf2ClientSecret : IClientSecret
{
    /// <summary>Number of PBKDF2 iterations used to derive the hash.</summary>
    int Iterations { get; }

    /// <summary>
    /// Random salt used during key derivation.
    /// </summary>
    /// <remarks>
    /// The framework treats this array as read-only after construction. Salt values are not
    /// secret; see <see cref="Pbkdf2ClientSecret"/> for buffer-ownership details.
    /// </remarks>
    byte[] Salt { get; }

    /// <summary>
    /// PBKDF2 output hash.
    /// </summary>
    /// <remarks>
    /// The framework treats this array as read-only after construction. Hash values are not
    /// secret; see <see cref="Pbkdf2ClientSecret"/> for buffer-ownership details.
    /// </remarks>
    byte[] Hash { get; }

    /// <summary>
    /// Returns a <see cref="Pbkdf2ClientSecret"/> holding <see cref="Iterations"/> and copies of
    /// <see cref="Salt"/> and <see cref="Hash"/>.
    /// </summary>
    /// <remarks>
    /// Every implementation of this interface gets this copy, so a store entity implementing it
    /// needs no copying code of its own. The copy is a <see cref="Pbkdf2ClientSecret"/> whatever
    /// the implementing type; an implementation that must keep its own type overrides this.
    /// </remarks>
    IClientCredential IClientCredential.Snapshot() =>
        new Pbkdf2ClientSecret(Iterations, [.. Salt], [.. Hash]);
}
