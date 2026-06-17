using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Tests.Clients;

/// <summary>
/// Tests for <see cref="ClientSecretHasher{TSecret}"/> behaviour that is only observable
/// through a concrete subclass that does NOT override
/// <see cref="ClientSecretHasher{TSecret}.CreateCore(System.ReadOnlySpan{char})"/>.
/// The base virtual fallback allocates a string and delegates to
/// <see cref="ClientSecretHasher{TSecret}.CreateCore(string)"/>; this code path is
/// bypassed by <see cref="Pbkdf2ClientSecretHasher"/> because it overrides both overloads.
/// </summary>
public sealed class ClientSecretHasherTests
{
    // ── Test double ──────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Minimal credential type associated with <see cref="StringOnlyHasher"/>.
    /// </summary>
    private sealed class StringOnlySecret : IClientSecret
    {
        public required string Value { get; init; }
    }

    /// <summary>
    /// Concrete hasher that overrides only <c>CreateCore(string)</c>, deliberately leaving
    /// <c>CreateCore(ReadOnlySpan&lt;char&gt;)</c> to the base-class virtual fallback.
    /// This isolates the fallback allocation path on <c>ClientSecretHasher&lt;T&gt;</c> line 82.
    /// </summary>
    private sealed class StringOnlyHasher : ClientSecretHasher<StringOnlySecret>
    {
        protected override StringOnlySecret CreateCore(string plaintext)
            => new() { Value = plaintext };

        protected override bool VerifyCore(StringOnlySecret stored, ReadOnlySpan<char> presented)
            => presented.SequenceEqual(stored.Value.AsSpan());
    }

    // ── CreateCore(ReadOnlySpan<char>) virtual fallback ──────────────────────────────────────────

    [Fact]
    public void Create_span_delegates_to_CreateCore_string_when_span_override_is_not_provided()
    {
        // Arrange
        var hasher = new StringOnlyHasher();

        // Act — exercises the base CreateCore(ReadOnlySpan<char>) virtual fallback (line 82)
        var stored = hasher.Create("my-secret".AsSpan());

        // Assert
        stored.Should().BeOfType<StringOnlySecret>()
            .Which.Value.Should().Be("my-secret");
    }

    [Fact]
    public void Create_span_via_base_fallback_produces_verifiable_credential()
    {
        var hasher = new StringOnlyHasher();

        var stored = hasher.Create("verify-me".AsSpan());

        hasher.Verify(stored, "verify-me".AsSpan()).Should().BeTrue();
        hasher.Verify(stored, "wrong".AsSpan()).Should().BeFalse();
    }

    [Fact]
    public void Create_span_via_base_fallback_preserves_full_unicode_content()
    {
        // Ensures the string allocation in the fallback handles non-ASCII correctly.
        var hasher = new StringOnlyHasher();

        var stored = hasher.Create("café-ñoño".AsSpan());

        hasher.Verify(stored, "café-ñoño".AsSpan()).Should().BeTrue();
    }

    [Fact]
    public void Create_span_via_base_fallback_throws_ArgumentException_for_empty_span()
    {
        var hasher = new StringOnlyHasher();

        var act = () => hasher.Create(ReadOnlySpan<char>.Empty);

        act.Should().Throw<ArgumentException>().WithParameterName("plaintext");
    }

    [Fact]
    public void Create_span_via_base_fallback_throws_ArgumentException_for_whitespace_only_span()
    {
        var hasher = new StringOnlyHasher();

        var act = () => hasher.Create("   ".AsSpan());

        act.Should().Throw<ArgumentException>().WithParameterName("plaintext");
    }
}
