using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>Tests for the <see cref="StoreKey"/> opaque, already-hashed key type (ADR 0013 §2).</summary>
public sealed class StoreKeyTests
{
    [Fact]
    public void ToString_returns_the_underlying_value()
    {
        var key = new StoreKey("zkd:code:e:abc123");

        key.ToString().Should().Be("zkd:code:e:abc123");
    }

    [Fact]
    public void Equals_StoreKey_returns_true_for_the_same_value()
    {
        var a = new StoreKey("same-value");
        var b = new StoreKey("same-value");

        a.Equals(b).Should().BeTrue();
    }

    [Fact]
    public void Equals_StoreKey_returns_false_for_different_values()
    {
        var a = new StoreKey("value-a");
        var b = new StoreKey("value-b");

        a.Equals(b).Should().BeFalse();
    }

    [Fact]
    public void Equals_object_returns_true_for_a_boxed_equal_StoreKey()
    {
        var a = new StoreKey("same-value");
        object b = new StoreKey("same-value");

        a.Equals(b).Should().BeTrue();
    }

    [Fact]
    public void Equals_object_returns_false_for_a_non_StoreKey_object()
    {
        var a = new StoreKey("same-value");

        a.Equals(new object()).Should().BeFalse();
    }

    [Fact]
    public void GetHashCode_is_equal_for_equal_keys()
    {
        var a = new StoreKey("same-value");
        var b = new StoreKey("same-value");

        a.GetHashCode().Should().Be(b.GetHashCode());
    }

    [Fact]
    public void Equality_operator_returns_true_for_equal_keys()
    {
        var a = new StoreKey("same-value");
        var b = new StoreKey("same-value");

        (a == b).Should().BeTrue();
    }

    [Fact]
    public void Equality_operator_returns_false_for_different_keys()
    {
        var a = new StoreKey("value-a");
        var b = new StoreKey("value-b");

        (a == b).Should().BeFalse();
    }

    [Fact]
    public void Inequality_operator_returns_false_for_equal_keys()
    {
        var a = new StoreKey("same-value");
        var b = new StoreKey("same-value");

        (a != b).Should().BeFalse();
    }

    [Fact]
    public void Inequality_operator_returns_true_for_different_keys()
    {
        var a = new StoreKey("value-a");
        var b = new StoreKey("value-b");

        (a != b).Should().BeTrue();
    }
}
