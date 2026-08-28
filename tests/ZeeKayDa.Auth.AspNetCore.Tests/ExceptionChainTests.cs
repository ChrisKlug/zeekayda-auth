namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// Pins the walking semantics of <see cref="ExceptionChain.FindInChain{T}"/>. The two host-startup
/// tests that use it cannot tell these cases apart, so they are asserted here directly (#555).
/// </summary>
public sealed class ExceptionChainTests
{
    private sealed class TargetException(Exception? inner = null)
        : Exception("target", inner);

    [Fact]
    public void FindInChain_returns_null_for_a_null_exception()
        => ExceptionChain.FindInChain<TargetException>(null).Should().BeNull();

    [Fact]
    public void FindInChain_returns_the_exception_itself_when_it_is_already_the_wanted_type()
    {
        var target = new TargetException();

        ExceptionChain.FindInChain<TargetException>(target).Should().BeSameAs(target);
    }

    [Fact]
    public void FindInChain_walks_InnerException()
    {
        var target = new TargetException();
        var outer = new InvalidOperationException("outer", new InvalidOperationException("middle", target));

        ExceptionChain.FindInChain<TargetException>(outer).Should().BeSameAs(target);
    }

    [Fact]
    public void FindInChain_searches_every_branch_of_an_AggregateException()
    {
        var target = new TargetException();
        var aggregate = new AggregateException(
            new InvalidOperationException("first branch"),
            new InvalidOperationException("second branch", target));

        ExceptionChain.FindInChain<TargetException>(aggregate).Should().BeSameAs(target);
    }

    [Fact]
    public void FindInChain_keeps_walking_past_an_AggregateException_that_holds_no_match()
    {
        // An AggregateException whose InnerExceptions contain no match, but whose own
        // InnerException chain does: the walk must fall through instead of giving up.
        var target = new TargetException();
        var aggregate = new AggregateException(new InvalidOperationException("no match here", target));

        ExceptionChain.FindInChain<TargetException>(aggregate).Should().BeSameAs(target);
    }

    [Fact]
    public void FindInChain_returns_null_when_the_chain_holds_no_match()
    {
        var chain = new AggregateException(
            new InvalidOperationException("a", new InvalidOperationException("b")));

        ExceptionChain.FindInChain<TargetException>(chain).Should().BeNull();
    }
}
