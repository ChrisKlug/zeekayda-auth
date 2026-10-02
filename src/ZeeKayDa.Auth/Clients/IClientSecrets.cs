namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Creates client secrets with the host's default <see cref="IClientSecretHasher"/>, and verifies a
/// presented secret against a client's stored ones in a time that reveals nothing when it fails.
/// </summary>
/// <remarks>
/// <para>
/// Implemented by the framework, to be consumed, never replaced: a new algorithm is an
/// <see cref="IClientSecretHasher"/>. A host that registers its own fails startup.
/// </para>
/// <para>
/// <strong>This is CPU-intensive.</strong> The default PBKDF2 hasher performs 600,000 iterations per
/// call (~600 ms on typical server hardware). <see cref="Create(string)"/> is meant for administrative
/// operations such as client registration or secret rotation, which must be rate-limited and
/// authenticated at the application layer.
/// </para>
/// <para>
/// <strong>The plaintext is sensitive.</strong> Never log, trace or serialise it, or pass it through
/// anything that may capture method arguments. A caller holding it in a <c>char[]</c> uses the span
/// overloads and zeroes the array afterwards; the string overload leaves a copy the garbage
/// collector erases when it pleases.
/// </para>
/// </remarks>
public interface IClientSecrets
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

    /// <summary>
    /// Whether <paramref name="presented"/> matches any of <paramref name="stored"/>, each verified by
    /// the hasher that declared its algorithm id.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A failure always costs the same: two verifications by every registered hasher, whichever
    /// secrets failed and however many there were — none included. So the time a refusal takes tells
    /// neither whether the client exists nor whether it is mid-rotation. A match returns at once.
    /// </para>
    /// <para>
    /// An authenticator that refuses a request before it has a secret to check — a malformed
    /// request, an unknown client — calls this with an empty <paramref name="presented"/>, which
    /// never matches and pays the full failure cost. A hasher that throws counts as a mismatch.
    /// </para>
    /// </remarks>
    /// <exception cref="ArgumentNullException"><paramref name="stored"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="stored"/> holds more than two secrets, the most a registered client may hold.
    /// </exception>
    bool Verify(ReadOnlySpan<char> presented, IReadOnlyCollection<ClientSecret> stored);
}
