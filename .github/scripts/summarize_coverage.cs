using System.Globalization;
using System.Xml.Linq;

try
{
    return Run(args);
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex.Message);
    return 1;
}

static int Run(string[] args)
{
    if (args.Length is not (1 or 2))
    {
        Console.Error.WriteLine("Usage: summarize_coverage.cs <results-dir> [label]");
        return 2;
    }

    // Optional label (e.g. the runner OS) distinguishes this table from the other build-and-test
    // matrix legs when GitHub stacks every job's summary together on the run's overview page.
    var label = args.Length == 2 ? args[1] : null;
    var packages = ReadPackages(args[0]);

    foreach (var package in packages)
    {
        Console.WriteLine(
            $"{package.Name}: line {FormatPercent(package.Lines.Percent)}, branch {FormatPercent(package.Branches.Percent)}");
    }

    WriteStepSummary(packages, label);

    return 0;
}

static IReadOnlyList<PackageCoverage> ReadPackages(string resultsDirectory)
{
    var coverageFiles = Directory
        .EnumerateFiles(resultsDirectory, "coverage.cobertura.xml", SearchOption.AllDirectories)
        .Order(StringComparer.Ordinal)
        .ToArray();

    if (coverageFiles.Length == 0)
    {
        throw new InvalidOperationException($"No coverage.cobertura.xml files found under {resultsDirectory}");
    }

    // Keyed (not appended) by package name: if a package's coverage is ever split across more
    // than one input file, totals are combined into a single row rather than shown as duplicates.
    var totals = new Dictionary<string, MutableCoverage>(StringComparer.Ordinal);

    foreach (var coverageFile in coverageFiles)
    {
        var root = XDocument.Load(coverageFile).Root
            ?? throw new InvalidOperationException($"{coverageFile} is not a valid Cobertura document.");

        foreach (var packageElement in root.Descendants("package"))
        {
            var name = packageElement.Attribute("name")?.Value;

            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            if (!totals.TryGetValue(name, out var coverage))
            {
                coverage = new MutableCoverage();
                totals[name] = coverage;
            }

            foreach (var lineElement in packageElement.Descendants("line"))
            {
                coverage.LinesValid += 1;

                if (ReadIntAttribute(lineElement, "hits", coverageFile) > 0)
                {
                    coverage.LinesCovered += 1;
                }

                if (!string.Equals(lineElement.Attribute("branch")?.Value, "true", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var (covered, valid) = ReadBranchCoverage(lineElement, coverageFile);
                coverage.BranchesCovered += covered;
                coverage.BranchesValid += valid;
            }
        }
    }

    return totals
        .OrderBy(static kvp => kvp.Key, StringComparer.Ordinal)
        .Select(static kvp => new PackageCoverage(
            kvp.Key,
            new CoverageMetric(kvp.Value.LinesCovered, kvp.Value.LinesValid),
            new CoverageMetric(kvp.Value.BranchesCovered, kvp.Value.BranchesValid)))
        .ToArray();
}

static int ReadIntAttribute(XElement element, string name, string coverageFile)
{
    var value = element.Attribute(name)?.Value;

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

static void WriteStepSummary(IReadOnlyList<PackageCoverage> packages, string? label)
{
    var summaryPath = Environment.GetEnvironmentVariable("GITHUB_STEP_SUMMARY");

    if (string.IsNullOrWhiteSpace(summaryPath))
    {
        return;
    }

    using var summary = File.AppendText(summaryPath);
    summary.WriteLine(string.IsNullOrWhiteSpace(label) ? "### Coverage Summary" : $"### Coverage Summary ({label})");
    summary.WriteLine();
    summary.WriteLine("| Package | Line | Branch |");
    summary.WriteLine("|---|---:|---:|");

    foreach (var package in packages)
    {
        summary.WriteLine(
            $"| {package.Name} | {FormatPercent(package.Lines.Percent)} | {FormatPercent(package.Branches.Percent)} |");
    }
}

static string FormatPercent(double? value)
    => value is null ? "n/a" : value.Value.ToString("F2", CultureInfo.InvariantCulture) + "%";

internal sealed record PackageCoverage(string Name, CoverageMetric Lines, CoverageMetric Branches);

internal sealed record CoverageMetric(int Covered, int Valid)
{
    public double? Percent => Valid == 0 ? null : Covered / (double)Valid * 100;
}

internal sealed class MutableCoverage
{
    public int LinesCovered { get; set; }

    public int LinesValid { get; set; }

    public int BranchesCovered { get; set; }

    public int BranchesValid { get; set; }
}
