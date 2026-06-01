using System.Diagnostics;
using System.Xml.Linq;

namespace ZeeKayDa.Auth.Tests.Configuration;

public sealed class CoverageRegressionScriptTests : IDisposable
{
    private readonly string tempDirectory = Path.Join(Path.GetTempPath(), "zeekayda-auth-coverage-script-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public void CheckCoverageRegression_FailsWhenLineOrBranchCoverageRegresses()
    {
        var baseResultsDirectory = Path.Join(tempDirectory, "base-results");
        var prResultsDirectory = Path.Join(tempDirectory, "pr-results");
        var baselineFile = Path.Join(tempDirectory, "coverage-baseline.json");

        WriteCoverageReport(baseResultsDirectory, "src/Example.cs", linesCovered: 8, linesValid: 10, branchesCovered: 4, branchesValid: 5);
        WriteCoverageReport(prResultsDirectory, "src/Example.cs", linesCovered: 7, linesValid: 10, branchesCovered: 3, branchesValid: 5);

        var writeBaseline = RunScript("--write-baseline", baseResultsDirectory, baselineFile);
        writeBaseline.ExitCode.Should().Be(0, writeBaseline.GetDebugOutput);

        var result = RunScript(prResultsDirectory, baselineFile);

        result.ExitCode.Should().Be(1, result.GetDebugOutput);
        result.GetDebugOutput.Should().Contain("line coverage 80.00% -> 70.00%");
        result.GetDebugOutput.Should().Contain("branch coverage 80.00% -> 60.00%");
        result.GetDebugOutput.Should().Contain("src/Example.cs");
    }

    [Fact]
    public void CheckCoverageRegression_PassesWhenCoverageImproves()
    {
        var baseResultsDirectory = Path.Join(tempDirectory, "base-results");
        var prResultsDirectory = Path.Join(tempDirectory, "pr-results");
        var baselineFile = Path.Join(tempDirectory, "coverage-baseline.json");

        WriteCoverageReport(baseResultsDirectory, "src/Example.cs", linesCovered: 7, linesValid: 10, branchesCovered: 3, branchesValid: 5);
        WriteCoverageReport(prResultsDirectory, "src/Example.cs", linesCovered: 9, linesValid: 10, branchesCovered: 5, branchesValid: 5);

        var writeBaseline = RunScript("--write-baseline", baseResultsDirectory, baselineFile);
        writeBaseline.ExitCode.Should().Be(0, writeBaseline.GetDebugOutput);

        var result = RunScript(prResultsDirectory, baselineFile);

        result.ExitCode.Should().Be(0, result.GetDebugOutput);
        result.GetDebugOutput.Should().Contain("Coverage regression check passed.");
    }

    public void Dispose()
    {
        if (Directory.Exists(tempDirectory))
        {
            Directory.Delete(tempDirectory, recursive: true);
        }
    }

    private static ScriptResult RunScript(params string[] scriptArguments)
    {
        var processStartInfo = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = FindRepositoryRoot(),
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        processStartInfo.ArgumentList.Add("run");
        processStartInfo.ArgumentList.Add(".github/scripts/check_coverage_regression.cs");
        processStartInfo.ArgumentList.Add("--");

        foreach (var scriptArgument in scriptArguments)
        {
            processStartInfo.ArgumentList.Add(scriptArgument);
        }

        using var process = Process.Start(processStartInfo)
            ?? throw new InvalidOperationException("Failed to start coverage regression script process.");

        process.WaitForExit();

        return new ScriptResult(
            process.ExitCode,
            process.StandardOutput.ReadToEnd(),
            process.StandardError.ReadToEnd());
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);

        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "ZeeKayDa.Auth.slnx")))
            {
                return current.FullName;
            }

            current = current.Parent;
        }

        throw new InvalidOperationException("Could not locate repository root from test base directory.");
    }

    private static void WriteCoverageReport(
        string resultsDirectory,
        string filePath,
        int linesCovered,
        int linesValid,
        int branchesCovered,
        int branchesValid)
    {
        Directory.CreateDirectory(resultsDirectory);

        var lines = new List<XElement>();

        for (var lineNumber = 1; lineNumber <= linesValid; lineNumber++)
        {
            var line = new XElement(
                "line",
                new XAttribute("number", lineNumber),
                new XAttribute("hits", lineNumber <= linesCovered ? 1 : 0));

            if (lineNumber <= branchesValid)
            {
                var isCoveredBranch = lineNumber <= branchesCovered;
                line.Add(new XAttribute("branch", "true"));
                line.Add(new XAttribute("condition-coverage", isCoveredBranch ? "100% (1/1)" : "0% (0/1)"));
            }
            else
            {
                line.Add(new XAttribute("branch", "false"));
            }

            lines.Add(line);
        }

        var document = new XDocument(
            new XElement(
                "coverage",
                new XAttribute("lines-covered", linesCovered),
                new XAttribute("lines-valid", linesValid),
                new XAttribute("branches-covered", branchesCovered),
                new XAttribute("branches-valid", branchesValid),
                new XElement(
                    "packages",
                    new XElement(
                        "package",
                        new XAttribute("name", "Example.Package"),
                        new XElement(
                            "classes",
                            new XElement(
                                "class",
                                new XAttribute("name", "Example.Class"),
                                new XAttribute("filename", filePath),
                                new XAttribute("line-rate", linesValid == 0 ? 0 : linesCovered / (double)linesValid),
                                new XAttribute("branch-rate", branchesValid == 0 ? 0 : branchesCovered / (double)branchesValid),
                                new XElement("lines", lines)))))));

        document.Save(Path.Join(resultsDirectory, "coverage.cobertura.xml"));
    }

    private sealed record ScriptResult(int ExitCode, string StandardOutput, string StandardError)
    {
        public string GetDebugOutput =>
            $"ExitCode: {ExitCode}{Environment.NewLine}STDOUT:{Environment.NewLine}{StandardOutput}{Environment.NewLine}STDERR:{Environment.NewLine}{StandardError}";
    }
}
