using System.Globalization;
using System.Xml.Linq;

try
{
    return Run(args);
}
catch (Exception ex)
{
    return Fail(ex.Message);
}

static int Run(string[] args)
{
    if (args.Length != 2)
    {
        Console.Error.WriteLine("Usage: check_coverage_regression.cs <pr-results-dir> <base-results-dir>");
        return 2;
    }

    var pr = ReadSummary(args[0]);
    var baseline = ReadSummary(args[1]);

    WriteStepSummary(pr, baseline);

    if (pr.Lines.Percent is null || baseline.Lines.Percent is null)
    {
        return Fail("Line coverage could not be computed.");
    }

    var allowedRegression = ReadAllowedRegression();
    var delta = pr.Lines.Percent.Value - baseline.Lines.Percent.Value;

    Console.WriteLine($"Base line coverage: {baseline.Lines.Percent.Value:F2}%");
    Console.WriteLine($"PR line coverage: {pr.Lines.Percent.Value:F2}%");
    Console.WriteLine($"Coverage delta: {delta:+0.00;-0.00;0.00} percentage points");

    if (delta < -allowedRegression)
    {
        return Fail(
            "Line coverage regressed by " +
            $"{Math.Abs(delta):F2} percentage points " +
            $"(allowed: {allowedRegression:F2}).");
    }

    return 0;
}

static CoverageSummary ReadSummary(string resultsDirectory)
{
    var coverageFiles = Directory
        .EnumerateFiles(resultsDirectory, "coverage.cobertura.xml", SearchOption.AllDirectories)
        .Order(StringComparer.Ordinal)
        .ToArray();

    if (coverageFiles.Length == 0)
    {
        throw new InvalidOperationException(
            $"No coverage.cobertura.xml files found under {resultsDirectory}");
    }

    var linesCovered = 0;
    var linesValid = 0;
    var branchesCovered = 0;
    var branchesValid = 0;

    foreach (var coverageFile in coverageFiles)
    {
        var root = XDocument.Load(coverageFile).Root
            ?? throw new InvalidOperationException($"{coverageFile} is not a valid Cobertura document.");

        linesCovered += ReadIntAttribute(root, "lines-covered", coverageFile);
        linesValid += ReadIntAttribute(root, "lines-valid", coverageFile);
        branchesCovered += ReadIntAttribute(root, "branches-covered", coverageFile);
        branchesValid += ReadIntAttribute(root, "branches-valid", coverageFile);
    }

    return new CoverageSummary(
        Lines: new CoverageMetric(linesCovered, linesValid),
        Branches: new CoverageMetric(branchesCovered, branchesValid));
}

static int ReadIntAttribute(XElement root, string name, string coverageFile)
{
    var value = root.Attribute(name)?.Value;

    if (value is null)
    {
        throw new InvalidOperationException(
            $"{coverageFile} is missing required Cobertura attribute '{name}'");
    }

    return int.Parse(value, CultureInfo.InvariantCulture);
}

static double ReadAllowedRegression()
{
    var value = Environment.GetEnvironmentVariable("COVERAGE_ALLOWED_REGRESSION_PERCENT");

    return string.IsNullOrWhiteSpace(value)
        ? 0
        : double.Parse(value, CultureInfo.InvariantCulture);
}

static void WriteStepSummary(CoverageSummary pr, CoverageSummary baseline)
{
    var summaryPath = Environment.GetEnvironmentVariable("GITHUB_STEP_SUMMARY");

    if (string.IsNullOrWhiteSpace(summaryPath))
    {
        return;
    }

    using var summary = File.AppendText(summaryPath);
    summary.WriteLine("### Coverage regression check");
    summary.WriteLine();
    summary.WriteLine("| Metric | Base | PR | Delta |");
    summary.WriteLine("|---|---:|---:|---:|");
    WriteSummaryRow(summary, "Line", baseline.Lines.Percent, pr.Lines.Percent);
    WriteSummaryRow(summary, "Branch", baseline.Branches.Percent, pr.Branches.Percent);
}

static void WriteSummaryRow(TextWriter writer, string metric, double? baseline, double? pr)
{
    writer.WriteLine($"| {metric} | {FormatPercent(baseline)} | {FormatPercent(pr)} | {FormatDelta(pr, baseline)} |");
}

static string FormatPercent(double? value)
    => value is null ? "n/a" : value.Value.ToString("F2", CultureInfo.InvariantCulture) + "%";

static string FormatDelta(double? pr, double? baseline)
    => pr is null || baseline is null
        ? "n/a"
        : (pr.Value - baseline.Value).ToString("+0.00;-0.00;0.00", CultureInfo.InvariantCulture) + " pp";

static int Fail(string message)
{
    Console.WriteLine($"::error::{message}");
    Console.Error.WriteLine(message);
    return 1;
}

internal sealed record CoverageSummary(CoverageMetric Lines, CoverageMetric Branches);

internal sealed record CoverageMetric(int Covered, int Valid)
{
    public double? Percent => Valid == 0 ? null : Covered / (double)Valid * 100;
}
