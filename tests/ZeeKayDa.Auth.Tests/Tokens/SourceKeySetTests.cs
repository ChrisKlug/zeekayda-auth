using System.Security.Cryptography;
using ZeeKayDa.Auth.Tokens;

namespace ZeeKayDa.Auth.Tests.Tokens;

/// <summary>
/// Exercises <see cref="SourceKeySet"/> and <see cref="SourceKeySet.FromSlots"/>: the Current-is-
/// required rule, and Previous/Next being independently optional.
/// </summary>
public sealed class SourceKeySetTests
{
    [Fact]
    public void FromSlots_throws_ZeeKayDaConfigurationException_when_Current_is_null()
    {
        var act = () => SourceKeySet.FromSlots(previous: null, current: null, next: null);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.no_current_key");
    }

    [Fact]
    public void FromSlots_succeeds_with_only_Current_configured()
    {
        var current = CreateRsaKey("current");

        var set = SourceKeySet.FromSlots(previous: null, current, next: null);

        set.SigningKey.Should().Be(current);
        set.Keys.Should().ContainSingle().Which.Should().Be(current);
    }

    [Fact]
    public void FromSlots_succeeds_with_only_Previous_and_Current_configured()
    {
        var previous = CreateRsaKey("previous");
        var current = CreateRsaKey("current");

        var set = SourceKeySet.FromSlots(previous, current, next: null);

        set.SigningKey.Should().Be(current);
        set.Keys.Should().BeEquivalentTo([previous, current]);
    }

    [Fact]
    public void FromSlots_succeeds_with_only_Current_and_Next_configured()
    {
        var current = CreateRsaKey("current");
        var next = CreateRsaKey("next");

        var set = SourceKeySet.FromSlots(previous: null, current, next);

        set.SigningKey.Should().Be(current);
        set.Keys.Should().BeEquivalentTo([current, next]);
    }

    [Fact]
    public void FromSlots_reports_the_signing_key_first_in_Keys()
    {
        var previous = CreateRsaKey("previous");
        var current = CreateRsaKey("current");
        var next = CreateRsaKey("next");

        var set = SourceKeySet.FromSlots(previous, current, next);

        set.Keys[0].Should().Be(current);
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_when_signingKey_is_null()
    {
        var act = () => new SourceKeySet(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void Constructor_throws_ZeeKayDaConfigurationException_when_alsoPublished_contains_a_null_element()
    {
        var current = CreateRsaKey("current");

        var act = () => new SourceKeySet(current, [null!]);

        act.Should().Throw<ZeeKayDaConfigurationException>()
            .Which.AggregatedFailures.Should().ContainSingle(f => f.Code == "signing.null_published_key");
    }

    private static SourceKey CreateRsaKey(string id)
    {
        using var rsa = RSA.Create(2048);
        var publicKey = PublicKeyParameters.FromRsa(rsa.ExportParameters(false));
        return new SourceKey(new KeyId(id), SigningAlgorithm.RS256, publicKey, DateTimeOffset.UtcNow.AddDays(90));
    }
}
