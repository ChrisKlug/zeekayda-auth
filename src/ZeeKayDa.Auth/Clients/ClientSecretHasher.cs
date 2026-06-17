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
/// Subclasses implement <see cref="VerifyCore"/> and <see cref="CreateCore(string)"/>. All cross-cutting
/// requirements — type guard, exception swallowing, and null/whitespace rejection — are handled
/// in this base class.
/// </para>
/// <para>
/// Subclasses MUST: use <see cref="CryptographicOperations.FixedTimeEquals"/> for all hash
/// comparisons; MUST NOT throw from <see cref="VerifyCore"/> (return <see langword="false"/>
/// instead); MUST NOT log the presented secret; and MUST be safe for concurrent use (singleton-safe).
/// </para>
/// <para>
/// The <see cref="IClientSecretHasher.Create(System.ReadOnlySpan{char})"/> span overload
/// eliminates a forced string allocation for callers who hold secrets in mutable buffers.
/// Subclasses that can consume a span directly should override
/// <see cref="CreateCore(System.ReadOnlySpan{char})"/> to avoid the fallback string allocation.
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
    public IClientSecret Create(ReadOnlySpan<char> plaintext)
    {
        if (MemoryExtensions.IsWhiteSpace(plaintext))
            throw new ArgumentException("Secret must not be empty or whitespace.", nameof(plaintext));

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
    /// Creates a new hashed credential from a validated plaintext secret span.
    /// </summary>
    /// <remarks>
    /// Default implementation allocates a string and delegates to <see cref="CreateCore(string)"/>.
    /// Subclasses may override to avoid the string allocation entirely.
    /// Called only after <see cref="IClientSecretHasher.Create(System.ReadOnlySpan{char})"/> has
    /// verified that <paramref name="plaintext"/> is non-empty and non-whitespace.
    /// </remarks>
    protected virtual TSecret CreateCore(ReadOnlySpan<char> plaintext) =>
        CreateCore(new string(plaintext));

    /// <summary>
    /// Creates a new hashed credential from a validated plaintext secret string.
    /// </summary>
    /// <remarks>
    /// Called only after the caller has verified that <paramref name="plaintext"/>
    /// is non-null and non-whitespace.
    /// </remarks>
    protected abstract TSecret CreateCore(string plaintext);
}
