using System.Security.Cryptography;

namespace ZeeKayDa.Auth.Clients;

/// <summary>
/// Base class for <see cref="IClientSecretHasher"/> implementations that handle a specific
/// <typeparamref name="TSecret"/> credential type.
/// </summary>
/// <typeparam name="TSecret">
/// The <see cref="IClientSecret"/> sub-type this hasher creates and verifies.
/// </typeparam>
/// <remarks>
/// <para>
/// Subclasses implement <see cref="VerifyCore"/> and <see cref="CreateCore"/>. All cross-cutting
/// requirements — type guard, exception swallowing, and null/whitespace rejection — are handled
/// in this base class.
/// </para>
/// <para>
/// Subclasses MUST: use <see cref="CryptographicOperations.FixedTimeEquals"/> for all hash
/// comparisons; MUST NOT throw from <see cref="VerifyCore"/> (return <see langword="false"/>
/// instead); MUST NOT log the presented secret; and MUST be safe for concurrent use (singleton-safe).
/// </para>
/// <para>
/// <strong>Managed-string limitation.</strong> The <see cref="Create"/> method accepts a
/// managed <see langword="string"/> whose contents the .NET garbage collector does not guarantee
/// to erase promptly. Callers should treat the created credential as potentially resident in
/// memory until the next GC cycle. <see cref="Verify"/> accepts a
/// <see cref="ReadOnlySpan{T}">ReadOnlySpan&lt;char&gt;</see>, so callers who hold the presented
/// secret in a <c>char[]</c> or similar mutable buffer can zero it out immediately after the call.
/// </para>
/// </remarks>
public abstract class ClientSecretHasher<TSecret> : IClientSecretHasher
    where TSecret : IClientSecret
{
    /// <inheritdoc/>
    public bool CanHandle(IClientSecret secret) => secret is TSecret;

    /// <inheritdoc/>
    public bool Verify(IClientSecret stored, ReadOnlySpan<char> presented)
    {
        if (stored is not TSecret typedStored)
            return false;

        try
        {
            return VerifyCore(typedStored, presented);
        }
        catch
        {
            return false;
        }
    }

    /// <inheritdoc/>
    public IClientSecret Create(string plaintext)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(plaintext);
        return CreateCore(plaintext);
    }

    /// <summary>
    /// Verifies a presented plaintext secret against a stored credential of type
    /// <typeparamref name="TSecret"/>.
    /// </summary>
    /// <remarks>
    /// Implementations MUST use <see cref="CryptographicOperations.FixedTimeEquals"/> for all
    /// hash comparisons, MUST NOT throw (return <see langword="false"/> on internal error), and
    /// MUST NOT log <paramref name="presented"/>.
    /// </remarks>
    protected abstract bool VerifyCore(TSecret stored, ReadOnlySpan<char> presented);

    /// <summary>
    /// Creates a new hashed credential from a validated plaintext secret.
    /// </summary>
    /// <remarks>
    /// Called only after <see cref="Create"/> has verified that <paramref name="plaintext"/>
    /// is non-null and non-whitespace.
    /// </remarks>
    protected abstract TSecret CreateCore(string plaintext);
}
