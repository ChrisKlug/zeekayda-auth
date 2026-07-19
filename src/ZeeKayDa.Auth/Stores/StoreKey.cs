namespace ZeeKayDa.Auth.Stores;

/// <summary>
/// An opaque, already-hashed persistence key for the authorization-code store (ADR 0013 §2).
/// </summary>
/// <remarks>
/// Constructed ONLY by the framework, from a raw code handle, via SHA-256. A backing-store
/// implementation receives <see cref="StoreKey"/> values and can persist them, use them as
/// dictionary/row keys, and compare them — but can never recover the raw handle, and so can
/// never persist a redeemable secret even by accident.
/// </remarks>
public readonly struct StoreKey : IEquatable<StoreKey>
{
    private readonly string _value;

    // Framework-only constructor — a backing store cannot fabricate a StoreKey from a raw
    // handle, making "hash the handle" (ADR 0013 §2) structurally unrepresentable to get wrong.
    internal StoreKey(string value) => _value = value;

    /// <summary>
    /// The safe, hashed string form — suitable as a Redis key or SQL primary key. Never the raw
    /// code handle.
    /// </summary>
    public override string ToString() => _value;

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
