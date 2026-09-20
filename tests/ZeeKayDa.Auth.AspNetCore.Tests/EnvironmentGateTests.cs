using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;

namespace ZeeKayDa.Auth.AspNetCore.Tests;

/// <summary>
/// The one decision every development-only resource asks for. The validators that call it prove
/// what each verdict is worded as; these prove which verdict a host gets.
/// </summary>
public sealed class EnvironmentGateTests
{
    private sealed class FakeHostEnvironment(string environmentName) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = environmentName;
        public string ApplicationName { get; set; } = "TestApp";
        public string ContentRootPath { get; set; } = "/";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Development_is_where_the_resource_is_expected_whatever_the_opt_out_says(bool allowOutsideDevelopment)
    {
        // The opt-out is about leaving Development, so inside it the flag changes nothing. A host
        // that sets it must not thereby turn a local Information record into a Critical one.
        var verdict = EnvironmentGate.Evaluate(new FakeHostEnvironment(Environments.Development), allowOutsideDevelopment);

        verdict.Should().Be(EnvironmentGate.Verdict.ExpectedInDevelopment);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("QA")]
    public void Outside_Development_without_an_opt_out_is_rejected(string environment)
    {
        var verdict = EnvironmentGate.Evaluate(new FakeHostEnvironment(environment), allowOutsideDevelopment: false);

        verdict.Should().Be(EnvironmentGate.Verdict.Rejected);
    }

    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    public void Outside_Development_the_opt_out_permits_the_resource(string environment)
    {
        var verdict = EnvironmentGate.Evaluate(new FakeHostEnvironment(environment), allowOutsideDevelopment: true);

        verdict.Should().Be(EnvironmentGate.Verdict.AllowedByOptOut);
    }

    [Fact]
    public void The_environment_name_is_matched_the_way_every_other_check_matches_it()
    {
        // IsDevelopment() compares ignoring case, so a host spelling it "development" is still in
        // Development. A gate stricter than the framework's own test would refuse to start a host
        // that every other check considers local.
        var verdict = EnvironmentGate.Evaluate(new FakeHostEnvironment("development"), allowOutsideDevelopment: false);

        verdict.Should().Be(EnvironmentGate.Verdict.ExpectedInDevelopment);
    }

    [Fact]
    public void A_null_environment_throws()
    {
        var act = () => EnvironmentGate.Evaluate(null!, allowOutsideDevelopment: false);

        act.Should().Throw<ArgumentNullException>();
    }
}
