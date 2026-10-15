using System.Security.Cryptography;
using System.Text;

namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// An opaque, already-hashed persistence key for a backing store.
/// </summary>
/// <remarks>
/// Built only by the framework, as <c>zkd:{store}:{kind}:{hex(sha256(value))}</c>, so a backing store can
/// key and compare by it but never recover, or accidentally persist, a redeemable handle.
/// </remarks>
public readonly struct StoreKey : IEquatable<StoreKey>
{
    private readonly string _value;

    internal StoreKey(string value) => _value = value;

    // One format, so a key in a shared backend says which store and record kind it belongs to.
    internal static StoreKey Hash(string store, string kind, string value) =>
        new($"zkd:{store}:{kind}:{Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)))}");

    /// <summary>
    /// The safe, hashed string form — suitable as a Redis key or SQL primary key. Never the raw
    /// handle.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown for <see langword="default"/>(<see cref="StoreKey"/>), which no framework path produces.
    /// </exception>
    public override string ToString() => Value;

    /// <inheritdoc/>
    public bool Equals(StoreKey other) => string.Equals(_value, other._value, StringComparison.Ordinal);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is StoreKey other && Equals(other);

    /// <inheritdoc/>
    /// <exception cref="InvalidOperationException">
    /// Thrown for <see langword="default"/>(<see cref="StoreKey"/>), as <see cref="ToString"/> is.
    /// </exception>
    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Value);

    private string Value => _value ?? throw new InvalidOperationException(
        $"{nameof(StoreKey)} was default-initialized; only the framework creates store keys.");

    /// <summary>Equality operator; see <see cref="Equals(StoreKey)"/>.</summary>
    public static bool operator ==(StoreKey left, StoreKey right) => left.Equals(right);

    /// <summary>Inequality operator; see <see cref="Equals(StoreKey)"/>.</summary>
    public static bool operator !=(StoreKey left, StoreKey right) => !left.Equals(right);
}
