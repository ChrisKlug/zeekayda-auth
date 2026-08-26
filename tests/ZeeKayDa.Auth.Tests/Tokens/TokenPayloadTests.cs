using System.Collections;
using System.Collections.Generic;

namespace ZeeKayDa.Auth.Tests.Tokens;

using ZeeKayDa.Auth.Tokens;

public sealed class TokenPayloadTests
{
    /// <summary>An <see cref="IReadOnlyDictionary{TKey,TValue}"/> whose enumerator yields the same
    /// claim name twice — the shape a hostile or buggy custom dictionary can present.</summary>
    private sealed class DuplicateKeyDictionary : IReadOnlyDictionary<string, object?>
    {
        private static readonly KeyValuePair<string, object?>[] Pairs =
        [
            new("sub", "alice"),
            new("sub", "attacker"),
        ];

        public object? this[string key] => "alice";
        public IEnumerable<string> Keys => Pairs.Select(p => p.Key);
        public IEnumerable<object?> Values => Pairs.Select(p => p.Value);
        public int Count => Pairs.Length;
        public bool ContainsKey(string key) => key == "sub";
        public bool TryGetValue(string key, out object? value) { value = "alice"; return ContainsKey(key); }
        public IEnumerator<KeyValuePair<string, object?>> GetEnumerator() => ((IEnumerable<KeyValuePair<string, object?>>)Pairs).GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    [Fact]
    public void Constructor_snapshots_the_claims_so_later_mutation_has_no_effect()
    {
        // The ring copies its signing input before signing for the same reason: what was
        // validated must be what gets signed.
        var source = new Dictionary<string, object?> { ["sub"] = "alice" };
        var payload = new TokenPayload(source);

        source["sub"] = "attacker";
        source["admin"] = true;

        payload.Claims["sub"].Should().Be("alice");
        payload.Claims.Should().NotContainKey("admin");
    }

    [Fact]
    public void Constructor_throws_ArgumentException_when_the_source_yields_a_duplicate_claim_name()
    {
        // RFC 7519 §4 leaves duplicate-member handling undefined, so a first-wins issuer and a
        // last-wins verifier would disagree about the subject. Rejected outright instead.
        var act = () => new TokenPayload(new DuplicateKeyDictionary());

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Constructor_throws_ArgumentNullException_if_claims_is_null()
    {
        var act = () => new TokenPayload(null!);

        act.Should().Throw<ArgumentNullException>();
    }

    [Fact]
    public void With_expression_snapshots_the_new_claims_too()
    {
        var payload = new TokenPayload(new Dictionary<string, object?> { ["sub"] = "alice" });
        var source = new Dictionary<string, object?> { ["sub"] = "bob" };

        var changed = payload with { Claims = source };
        source["sub"] = "attacker";

        changed.Claims["sub"].Should().Be("bob");
    }
}
