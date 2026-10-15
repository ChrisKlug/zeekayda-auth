using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Creates and verifies hashed client secrets for the algorithm ids it declares.
/// </summary>
/// <remarks>
/// <para>
/// The framework reads the algorithm id between a <see cref="ClientSecret.Value"/>'s first two <c>$</c>
/// and calls the hasher declaring it, with the whole string; <see cref="PhcString"/> helps parse the rest.
/// </para>
/// <para>
/// The framework counts a throwing <see cref="Verify"/> as a failure, never passes <see cref="Create"/>
/// blank input, and refuses a created id this hasher did not declare. The implementation compares in
/// fixed time (<see cref="CryptographicOperations.FixedTimeEquals"/>), never logs the presented secret, and
/// is safe for concurrent use.
/// </para>
/// <para>
/// Register with <c>AddClientSecretHasher&lt;T&gt;()</c>; two hashers declaring one id fail startup.
/// </para>
/// </remarks>
public interface IClientSecretHasher
{
    /// <summary>
    /// The algorithm ids this hasher owns, for example <c>{ "pbkdf2-sha256" }</c>, or bcrypt's
    /// <c>{ "2a", "2b", "2y" }</c>. Compared ordinally; each is 1–32 characters from <c>[a-z0-9-]</c>.
    /// </summary>
    IReadOnlySet<string> AlgorithmIds { get; }

    /// <summary>
    /// Verifies a presented plaintext secret against a stored one whose algorithm id this hasher
    /// declared. Returns <see langword="false"/> on mismatch or on a stored value it cannot read.
    /// </summary>
    bool Verify(ReadOnlySpan<char> presented, ClientSecret stored);

    /// <summary>
    /// Hashes a plaintext secret. The framework has already refused empty and whitespace-only input.
    /// </summary>
    /// <remarks>
    /// A span, so a caller can zero its <c>char[]</c> afterwards. Callers go through <see cref="ClientSecrets"/>.
    /// </remarks>
    ClientSecret Create(ReadOnlySpan<char> plaintext);

    /// <summary>
    /// Returns what is wrong with a stored secret whose algorithm id this hasher declared — a value
    /// it cannot parse, or a work factor below its floor. Empty when the secret is acceptable.
    /// </summary>
    /// <remarks>
    /// Runs on every client lookup, unauthenticated ones included, so it parses and never derives. Messages
    /// reach the operator's log verbatim, so they never contain the stored value or an exception's message.
    /// </remarks>
    IEnumerable<ZeeKayDaConfigurationFailure> ValidateStoredSecret(ClientSecret stored) => [];

    /// <summary>
    /// The stored secret failure-path padding verifies against: as costly to verify as a real one, and
    /// matching no value a caller can know.
    /// </summary>
    /// <remarks>
    /// Internal, so a third-party hasher cannot supply a cheaper decoy that would reopen the timing oracle; it
    /// pays one real <see cref="Create"/> at startup instead.
    /// </remarks>
    internal ClientSecret CreateTimingDecoy() =>
        Create(Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)));
}
