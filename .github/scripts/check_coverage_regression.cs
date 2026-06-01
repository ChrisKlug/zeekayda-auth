using System.Globalization;
using System.Text.Json;
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
    if (args.Length == 3 && args[0] == "--write-baseline")
    {
        var summary = ReadSummary(args[1]);
        WriteBaseline(summary, args[2]);
        Console.WriteLine($"Wrote coverage baseline to {args[2]}");
        return 0;
    }

    if (args.Length != 2)
    {
        Console.Error.WriteLine("Usage: check_coverage_regression.cs <pr-results-dir> <baseline-file>");
        Console.Error.WriteLine("   or: check_coverage_regression.cs --write-baseline <results-dir> <baseline-file>");
        return 2;
    }

    var pr = ReadSummary(args[0]);
    var baseline = ReadBaseline(args[1]);

    WriteStepSummary(pr, baseline);

    var allowedRegression = ReadAllowedRegression();
    var failures = new List<string>();

    CheckRegression("Line", baseline.LinePercent, pr.Lines.Percent, allowedRegression, failures);
    CheckRegression("Branch", baseline.BranchPercent, pr.Branches.Percent, allowedRegression, failures);

    Console.WriteLine($"Base line coverage: {FormatPercent(baseline.LinePercent)}");
    Console.WriteLine($"PR line coverage: {FormatPercent(pr.Lines.Percent)}");
    Console.WriteLine($"Base branch coverage: {FormatPercent(baseline.BranchPercent)}");
    Console.WriteLine($"PR branch coverage: {FormatPercent(pr.Branches.Percent)}");

    WriteRegressedFiles(pr, baseline, allowedRegression);

    if (failures.Count > 0)
    {
        return Fail($"Coverage regression detected: {string.Join("; ", failures)}");
    }

    Console.WriteLine("Coverage regression check passed.");
    return 0;
}

static void CheckRegression(string metric, double? baseline, double? current, double allowedRegression, List<string> failures)
{
    if (baseline is null || current is null)
    {
        failures.Add($"{metric} coverage could not be computed.");
        return;
    }

    var delta = current.Value - baseline.Value;

    Console.WriteLine(
        $"{metric} coverage delta: {delta:+0.00;-0.00;0.00} percentage points " +
        $"(baseline: {baseline.Value:F2}%, current: {current.Value:F2}%, allowed: {allowedRegression:F2} pp)");

    if (delta < -allowedRegression)
    {
        failures.Add(
            $"{metric.ToLowerInvariant()} coverage {baseline.Value:F2}% -> {current.Value:F2}% " +
            $"(delta {delta:+0.00;-0.00;0.00} pp, allowed -{allowedRegression:F2} pp)");
    }
}

static void WriteRegressedFiles(CoverageSummary pr, CoverageBaseline baseline, double allowedRegression)
{
    var regressedFiles = baseline.Files
        .Select(kvp =>
        {
            if (!pr.Files.TryGetValue(kvp.Key, out var current))
            {
                return null;
            }

            var lineDelta = TryDelta(current.Lines.Percent, kvp.Value.LinePercent);
            var branchDelta = TryDelta(current.Branches.Percent, kvp.Value.BranchPercent);

            if ((lineDelta ?? 0) >= -allowedRegression && (branchDelta ?? 0) >= -allowedRegression)
            {
                return null;
            }

            return new FileRegression(kvp.Key, kvp.Value.LinePercent, current.Lines.Percent, lineDelta, kvp.Value.BranchPercent, current.Branches.Percent, branchDelta);
        })
        .Where(static item => item is not null)
        .Cast<FileRegression>()
        .OrderBy(item => Math.Min(item.LineDelta ?? 0, item.BranchDelta ?? 0))
        .Take(10)
        .ToArray();

    if (regressedFiles.Length == 0)
    {
        return;
    }

    Console.WriteLine("Files with coverage regressions (top 10):");

    foreach (var file in regressedFiles)
    {
        Console.WriteLine(
            $"  - {file.Path}: " +
            $"line {FormatPercent(file.BaselineLine)} -> {FormatPercent(file.CurrentLine)} ({FormatDelta(file.LineDelta)}), " +
            $"branch {FormatPercent(file.BaselineBranch)} -> {FormatPercent(file.CurrentBranch)} ({FormatDelta(file.BranchDelta)})");
    }
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
    var fileTotals = new Dictionary<string, MutableCoverage>(StringComparer.Ordinal);

    foreach (var coverageFile in coverageFiles)
    {
        var root = XDocument.Load(coverageFile).Root
            ?? throw new InvalidOperationException($"{coverageFile} is not a valid Cobertura document.");

        linesCovered += ReadIntAttribute(root, "lines-covered", coverageFile);
        linesValid += ReadIntAttribute(root, "lines-valid", coverageFile);
        branchesCovered += ReadIntAttribute(root, "branches-covered", coverageFile);
        branchesValid += ReadIntAttribute(root, "branches-valid", coverageFile);

        foreach (var classElement in root.Descendants("class"))
        {
            var filePath = classElement.Attribute("filename")?.Value;

            if (string.IsNullOrWhiteSpace(filePath))
            {
                continue;
            }

            var normalizedPath = NormalizePath(filePath);

            if (!fileTotals.TryGetValue(normalizedPath, out var totals))
            {
                totals = new MutableCoverage();
                fileTotals[normalizedPath] = totals;
            }

            foreach (var lineElement in classElement.Descendants("line"))
            {
                totals.LinesValid += 1;

                if (ReadIntAttribute(lineElement, "hits", coverageFile) > 0)
                {
                    totals.LinesCovered += 1;
                }

                if (!string.Equals(lineElement.Attribute("branch")?.Value, "true", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var (covered, valid) = ReadBranchCoverage(lineElement, coverageFile);
                totals.BranchesCovered += covered;
                totals.BranchesValid += valid;
            }
        }
    }

    var files = fileTotals.ToDictionary(
        static kvp => kvp.Key,
        static kvp => new CoverageFileSummary(
            new CoverageMetric(kvp.Value.LinesCovered, kvp.Value.LinesValid),
            new CoverageMetric(kvp.Value.BranchesCovered, kvp.Value.BranchesValid)),
        StringComparer.Ordinal);

    return new CoverageSummary(
        Lines: new CoverageMetric(linesCovered, linesValid),
        Branches: new CoverageMetric(branchesCovered, branchesValid),
        Files: files);
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

static (int Covered, int Valid) ReadBranchCoverage(XElement lineElement, string coverageFile)
{
    var coverage = lineElement.Attribute("condition-coverage")?.Value;

    if (string.IsNullOrWhiteSpace(coverage))
    {
        return (0, 0);
    }

    var start = coverage.LastIndexOf('(');
    var end = coverage.LastIndexOf(')');

    if (start < 0 || end <= start + 1)
    {
        throw new InvalidOperationException($"{coverageFile} has invalid condition-coverage value '{coverage}'.");
    }

    var counts = coverage.Substring(start + 1, end - start - 1).Split('/');

    if (counts.Length != 2)
    {
        throw new InvalidOperationException($"{coverageFile} has invalid condition-coverage value '{coverage}'.");
    }

    return (
        Covered: int.Parse(counts[0], CultureInfo.InvariantCulture),
        Valid: int.Parse(counts[1], CultureInfo.InvariantCulture));
}

static string NormalizePath(string path)
    => path.Replace('\\', '/');

static double ReadAllowedRegression()
{
    var value = Environment.GetEnvironmentVariable("COVERAGE_ALLOWED_REGRESSION_PERCENT");

    return string.IsNullOrWhiteSpace(value)
        ? 0
        : double.Parse(value, CultureInfo.InvariantCulture);
}

static CoverageBaseline ReadBaseline(string baselinePath)
{
    if (!File.Exists(baselinePath))
    {
        throw new InvalidOperationException($"Coverage baseline file not found: {baselinePath}");
    }

    using var document = JsonDocument.Parse(File.ReadAllText(baselinePath));
    var root = document.RootElement;

    if (root.ValueKind != JsonValueKind.Object)
    {
        throw new InvalidOperationException($"Coverage baseline file '{baselinePath}' is invalid.");
    }

    var files = new Dictionary<string, CoverageBaselineMetric>(StringComparer.Ordinal);

    if (root.TryGetProperty("files", out var filesElement) && filesElement.ValueKind == JsonValueKind.Object)
    {
        foreach (var fileProperty in filesElement.EnumerateObject())
        {
            if (fileProperty.Value.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            files[NormalizePath(fileProperty.Name)] = new CoverageBaselineMetric(
                LinePercent: ReadNullableDouble(fileProperty.Value, "linePercent"),
                BranchPercent: ReadNullableDouble(fileProperty.Value, "branchPercent"));
        }
    }

    return new CoverageBaseline(
        LinePercent: ReadNullableDouble(root, "linePercent"),
        BranchPercent: ReadNullableDouble(root, "branchPercent"),
        Files: files);
}

static void WriteBaseline(CoverageSummary summary, string baselinePath)
{
    using var stream = File.Create(baselinePath);
    using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });

    writer.WriteStartObject();
    WriteNullableNumber(writer, "linePercent", summary.Lines.Percent);
    WriteNullableNumber(writer, "branchPercent", summary.Branches.Percent);
    writer.WritePropertyName("files");
    writer.WriteStartObject();

    foreach (var file in summary.Files.OrderBy(static kvp => kvp.Key, StringComparer.Ordinal))
    {
        writer.WritePropertyName(file.Key);
        writer.WriteStartObject();
        WriteNullableNumber(writer, "linePercent", file.Value.Lines.Percent);
        WriteNullableNumber(writer, "branchPercent", file.Value.Branches.Percent);
        writer.WriteEndObject();
    }

    writer.WriteEndObject();
    writer.WriteEndObject();
    writer.Flush();
}

static double? ReadNullableDouble(JsonElement element, string propertyName)
{
    if (!element.TryGetProperty(propertyName, out var property) || property.ValueKind == JsonValueKind.Null)
    {
        return null;
    }

    return property.GetDouble();
}

static void WriteNullableNumber(Utf8JsonWriter writer, string name, double? value)
{
    if (value is null)
    {
        writer.WriteNull(name);
        return;
    }

    writer.WriteNumber(name, value.Value);
}

static void WriteStepSummary(CoverageSummary pr, CoverageBaseline baseline)
{
    var summaryPath = Environment.GetEnvironmentVariable("GITHUB_STEP_SUMMARY");

    if (string.IsNullOrWhiteSpace(summaryPath))
    {
        return;
    }

    using var summary = File.AppendText(summaryPath);
    summary.WriteLine("### Coverage regression check");
    summary.WriteLine();
    summary.WriteLine("| Metric | Baseline | PR | Delta |");
    summary.WriteLine("|---|---:|---:|---:|");
    WriteSummaryRow(summary, "Line", baseline.LinePercent, pr.Lines.Percent);
    WriteSummaryRow(summary, "Branch", baseline.BranchPercent, pr.Branches.Percent);
}

static void WriteSummaryRow(TextWriter writer, string metric, double? baseline, double? pr)
{
    writer.WriteLine($"| {metric} | {FormatPercent(baseline)} | {FormatPercent(pr)} | {FormatDelta(TryDelta(pr, baseline))} |");
}

static double? TryDelta(double? current, double? baseline)
    => current is null || baseline is null
        ? null
        : current.Value - baseline.Value;

static string FormatPercent(double? value)
    => value is null ? "n/a" : value.Value.ToString("F2", CultureInfo.InvariantCulture) + "%";

static string FormatDelta(double? value)
    => value is null
        ? "n/a"
        : value.Value.ToString("+0.00;-0.00;0.00", CultureInfo.InvariantCulture) + " pp";

static int Fail(string message)
{
    Console.WriteLine($"::error::{message}");
    Console.Error.WriteLine(message);
    return 1;
}

internal sealed record CoverageSummary(CoverageMetric Lines, CoverageMetric Branches, IReadOnlyDictionary<string, CoverageFileSummary> Files);

internal sealed record CoverageFileSummary(CoverageMetric Lines, CoverageMetric Branches);

internal sealed record CoverageMetric(int Covered, int Valid)
{
    public double? Percent => Valid == 0 ? null : Covered / (double)Valid * 100;
}

internal sealed record CoverageBaseline(double? LinePercent, double? BranchPercent, IReadOnlyDictionary<string, CoverageBaselineMetric> Files);

internal sealed record CoverageBaselineMetric(double? LinePercent, double? BranchPercent);

internal sealed record FileRegression(
    string Path,
    double? BaselineLine,
    double? CurrentLine,
    double? LineDelta,
    double? BaselineBranch,
    double? CurrentBranch,
    double? BranchDelta);

internal sealed class MutableCoverage
{
    public int LinesCovered { get; set; }

    public int LinesValid { get; set; }

    public int BranchesCovered { get; set; }

    public int BranchesValid { get; set; }
}
