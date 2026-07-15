using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Tests for <see cref="StoreKeyGenerator"/>: raw code/token handle generation. Unaffected by
/// ADR 0013 (the authorization-code store protocol/persistence split) — this type generates the
/// raw handle handed to a store, distinct from the framework-internal <see cref="StoreKey"/>
/// that wraps the already-hashed persistence key.
/// </summary>
public sealed class StoreKeyGeneratorTests
{
    [Fact]
    public void Generate_produces_10000_distinct_keys()
    {
        var keys = Enumerable.Range(0, 10_000)
            .Select(_ => StoreKeyGenerator.Generate())
            .ToList();

        keys.Should().OnlyHaveUniqueItems(because: "no two generated handles should collide in 10,000 samples");
    }

    [Fact]
    public void Generate_keys_are_43_characters()
    {
        // Base64Url(32 bytes) = ceil(32 * 4 / 3) with no padding = 43 characters
        var keys = Enumerable.Range(0, 100).Select(_ => StoreKeyGenerator.Generate()).ToList();

        keys.Should().AllSatisfy(k => k.Length.Should().Be(43,
            because: "32 bytes Base64Url-encoded without padding produces exactly 43 characters"));
    }

    [Fact]
    public void Generate_keys_contain_only_Base64Url_characters()
    {
        var validChars = new HashSet<char>("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");

        var keys = Enumerable.Range(0, 100).Select(_ => StoreKeyGenerator.Generate()).ToList();

        keys.Should().AllSatisfy(k =>
            k.ToCharArray().Should().AllSatisfy(c =>
                validChars.Contains(c).Should().BeTrue(
                    because: $"Base64Url keys must only use URL-safe characters, but found '{c}'")));
    }

    [Fact]
    public void StoreKeyGenerator_is_in_ZeeKayDa_Auth_Stores_namespace()
    {
        typeof(StoreKeyGenerator).Namespace.Should().Be("ZeeKayDa.Auth.Stores");
    }
}
