using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Creates and verifies hashed client secrets for the algorithm ids it declares.
/// </summary>
/// <remarks>
/// <para>
/// The framework reads the algorithm id from a <see cref="ClientSecret.Value"/> — the text between
/// its first two <c>$</c> — and calls the hasher whose <see cref="AlgorithmIds"/> contains it. The
/// hasher receives the whole string and parses the rest itself; <see cref="PhcString"/> helps
/// where the format is PHC.
/// </para>
/// <para>
/// The framework enforces the rules around every call: a <see cref="Verify"/> that throws counts as
/// a failed verification, empty and whitespace-only plaintext never reaches <see cref="Create"/>,
/// and a <see cref="Create"/> result whose id this hasher did not declare is refused. What remains
/// the implementation's job: compare in fixed time (e.g.
/// <see cref="CryptographicOperations.FixedTimeEquals"/>), never log the presented secret, and be
/// safe for concurrent use.
/// </para>
/// <para>
/// Register with <c>AddClientSecretHasher&lt;T&gt;()</c>. Two registered hashers declaring the same
/// id fail startup.
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
    /// A span, so a caller holding the plaintext in a <c>char[]</c> can zero it afterwards. Callers
    /// go through <see cref="IClientSecrets"/>, never through a hasher directly.
    /// </remarks>
    ClientSecret Create(ReadOnlySpan<char> plaintext);

    /// <summary>
    /// Returns what is wrong with a stored secret whose algorithm id this hasher declared — a value
    /// it cannot parse, or a work factor below its floor. Empty when the secret is acceptable.
    /// </summary>
    /// <remarks>
    /// Runs wherever a client registration is validated. The framework puts the client id in front
    /// of each message. Every message reaches the operator's log verbatim, so it describes the
    /// problem and never contains any part of the stored value, or a caught exception's message.
    /// </remarks>
    IEnumerable<ZeeKayDaConfigurationFailure> ValidateStoredSecret(ClientSecret stored) => [];

    /// <summary>
    /// Creates the stored secret that failure-path timing padding verifies against: one that costs
    /// this hasher exactly as much to verify as a real secret, and that no value a caller can know
    /// will verify.
    /// </summary>
    /// <remarks>
    /// Internal on purpose. A third-party hasher inherits this default, which pays one real
    /// <see cref="Create"/> of a random value, once, at startup. It cannot supply a cheaper decoy of
    /// its own: one that verified faster than a real secret would reopen the timing oracle the
    /// padding exists to close, and nothing would report it. A built-in hasher overrides this where
    /// it can build the decoy without the derivation.
    /// </remarks>
    internal ClientSecret CreateTimingDecoy() =>
        Create(Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)));
}
