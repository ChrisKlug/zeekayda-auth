namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Hashes a new client secret with the host's default <see cref="IClientSecretHasher"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This is CPU-intensive.</strong> The default PBKDF2 hasher performs 600,000 iterations per
/// call (~600 ms on typical server hardware). Do not call it on a hot request path; it is meant for
/// administrative operations such as client registration or secret rotation, which must be
/// rate-limited and authenticated at the application layer.
/// </para>
/// <para>
/// <strong>The plaintext is sensitive.</strong> Never log, trace or serialise it, or pass it through
/// anything that may capture method arguments. A caller holding it in a <c>char[]</c> uses the span
/// overload and zeroes the array afterwards; the string overload leaves a copy the garbage
/// collector erases when it pleases.
/// </para>
/// </remarks>
public interface IClientSecretFactory
{
    /// <summary>Hashes <paramref name="plaintext"/> with the default hasher.</summary>
    /// <exception cref="ArgumentNullException"><paramref name="plaintext"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException"><paramref name="plaintext"/> is empty or whitespace.</exception>
    ClientSecret Create(string plaintext);

    /// <summary>Hashes <paramref name="plaintext"/> with the default hasher.</summary>
    /// <exception cref="ArgumentException">
    /// <paramref name="plaintext"/> is empty or whitespace.
    /// </exception>
    ClientSecret Create(ReadOnlySpan<char> plaintext);
}
