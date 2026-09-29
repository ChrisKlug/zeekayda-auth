using System.Security.Cryptography;
using System.Text;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// An opaque, already-hashed persistence key for a backing store.
/// </summary>
/// <remarks>
/// Constructed ONLY by the framework, as <c>zkd:{store}:{kind}:{hex(sha256(value))}</c>. A backing-store
/// implementation receives <see cref="StoreKey"/> values and can persist them, use them as
/// dictionary/row keys, and compare them — but can never recover the raw handle, and so can
/// never persist a redeemable secret even by accident.
/// </remarks>
public readonly struct StoreKey : IEquatable<StoreKey>
{
    private readonly string _value;

    // Framework-only constructor — a backing store cannot fabricate a StoreKey from a raw
    // handle, making "hash the handle" structurally unrepresentable to get wrong.
    internal StoreKey(string value) => _value = value;

    // The one key format every store uses, so a key in a shared backend says which store and
    // which kind of record it belongs to.
    internal static StoreKey Hash(string store, string kind, string value) =>
        new($"zkd:{store}:{kind}:{Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)))}");

    /// <summary>
    /// The safe, hashed string form — suitable as a Redis key or SQL primary key. Never the raw
    /// handle.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown for <see langword="default"/>(<see cref="StoreKey"/>), which no framework path produces.
    /// </exception>
    public override string ToString() => _value ?? throw new InvalidOperationException(
        $"{nameof(StoreKey)} was default-initialized; only the framework creates store keys.");

    /// <inheritdoc/>
    public bool Equals(StoreKey other) => string.Equals(_value, other._value, StringComparison.Ordinal);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is StoreKey other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(_value);

    /// <summary>Equality operator; see <see cref="Equals(StoreKey)"/>.</summary>
    public static bool operator ==(StoreKey left, StoreKey right) => left.Equals(right);

    /// <summary>Inequality operator; see <see cref="Equals(StoreKey)"/>.</summary>
    public static bool operator !=(StoreKey left, StoreKey right) => !left.Equals(right);
}
