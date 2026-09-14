using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
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

    [Fact]
    public void GetEdges_keys_a_marked_literal_endpoint_on_its_exact_path()
    {
        var endpoint = MarkedEndpoint(RoutePatternFactory.Parse("/tenant1/connect/token"));

        var edges = new ExactPathMatcherPolicy().GetEdges([endpoint]);

        edges.Should().ContainSingle().Which.Endpoints.Should().ContainSingle().Which.Should().BeSameAs(endpoint);
    }
}
