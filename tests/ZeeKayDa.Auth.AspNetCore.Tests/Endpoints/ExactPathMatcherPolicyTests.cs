using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Matching;
using Microsoft.AspNetCore.Routing.Patterns;
using ZeeKayDa.Auth.AspNetCore.Endpoints;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Endpoints;

public sealed class ExactPathMatcherPolicyTests
{
    private static RouteEndpoint MarkedEndpoint(RoutePattern pattern) => new(
        _ => Task.CompletedTask,
        pattern,
        order: 0,
        new EndpointMetadataCollection(ExactPathMetadata.Instance),
        displayName: "marked");

    [Fact]
    public void GetEdges_refuses_a_marked_endpoint_whose_route_has_a_parameter()
    {
        var endpoint = MarkedEndpoint(RoutePatternFactory.Parse("/tenant1/connect/{name}"));

        var act = () => new ExactPathMatcherPolicy().GetEdges([endpoint]);

        act.Should().Throw<InvalidOperationException>(
            because: "a parameterised route has no single exact path, so it would 404 every request")
            .WithMessage("*not a literal path*");
    }

    [Fact]
    public void GetEdges_refuses_a_marked_endpoint_whose_route_has_no_raw_text()
    {
        var endpoint = MarkedEndpoint(RoutePatternFactory.Pattern(
            RoutePatternFactory.Segment(RoutePatternFactory.LiteralPart("connect"))));

        var act = () => new ExactPathMatcherPolicy().GetEdges([endpoint]);

        act.Should().Throw<InvalidOperationException>(
            because: "without raw text there is nothing to compare the request path against")
            .WithMessage("*not a literal path*");
    }

    [Theory]
    [InlineData("/tenant1/connect/token", Destination)]
    [InlineData("/TENANT1/connect/token", Exit)]
    [InlineData("/tenant1/connect/token/", Exit)]
    [InlineData("/connect/token", Exit)]
    public void Jump_table_selects_a_marked_endpoint_only_for_its_exact_path(string requestPath, int expected)
    {
        var policy = new ExactPathMatcherPolicy();
        var edge = policy.GetEdges([MarkedEndpoint(RoutePatternFactory.Parse("/tenant1/connect/token"))]).Should().ContainSingle().Subject;
        var table = policy.BuildJumpTable(Exit, [new PolicyJumpTableEdge(edge.State, Destination)]);

        var destination = table.GetDestination(new DefaultHttpContext { Request = { Path = requestPath } });

        destination.Should().Be(expected,
            because: "the edge must be keyed on the route's exact path, and any other path must exit the node");
    }

    private const int Destination = 7;
    private const int Exit = -1;
}
