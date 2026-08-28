using System.Globalization;
using System.Text;
using System.Text.Json;

// Builds the weekly mutation-score report for the tracking issue that mutation.yml maintains
// (#585). Reads each matrix leg's Stryker mutation-report.json artifact, renders the current
// scores as a markdown table, and decides whether anything moved since the previous run.
//
// The previous run's numbers are read back from a machine-readable block embedded in the issue
// body, so the issue is its own state store — no cache, no artifact retention window to outlive.
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
    if (args.Length is not (3 or 4))
    {
        Console.Error.WriteLine(
            "Usage: report_mutation_scores.cs <artifacts-dir> <previous-body-file> <output-dir> [run-date]");
        return 2;
    }

    var runDate = args.Length == 4 && !string.IsNullOrWhiteSpace(args[3])
        ? args[3]
        : DateTime.UtcNow.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    var legs = ReadLegs(args[0]);
    var previous = ReadPreviousScores(args[1]);
    var rows = BuildRows(legs, previous);

    if (rows.Count == 0)
    {
        return Fail($"No mutation reports found under {args[0]} and no previous scores to compare against.");
    }

    var changes = rows.Where(static row => row.HasMoved).ToArray();

    Directory.CreateDirectory(args[2]);
    File.WriteAllText(Path.Combine(args[2], "body.md"), RenderBody(rows, runDate));

    if (changes.Length > 0)
    {
        File.WriteAllText(Path.Combine(args[2], "comment.md"), RenderComment(rows, changes, runDate));
    }

    foreach (var row in rows)
    {
        Console.WriteLine($"{row.Key}: {FormatScore(row.Current)} (previous {FormatScore(row.Previous)})");
    }

    Console.WriteLine(changes.Length > 0
        ? $"{changes.Length} row(s) moved since the previous run."
        : "No row moved since the previous run; the body is refreshed but no comment is posted.");

    WriteOutput("changed", changes.Length > 0 ? "true" : "false");
    return 0;
}

// A leg's artifact directory is named 'mutation-report-<target>[-<slice>]'. Target project names
// never contain '-', so the first '-' after the prefix is the target/slice boundary.
static IReadOnlyDictionary<string, MutantTotals?> ReadLegs(string artifactsDirectory)
{
    var legs = new Dictionary<string, MutantTotals?>(StringComparer.Ordinal);

    if (!Directory.Exists(artifactsDirectory))
    {
        return legs;
    }

    var artifactDirectories = Directory
        .EnumerateDirectories(artifactsDirectory, Report.ArtifactPrefix + "*", SearchOption.TopDirectoryOnly)
        .Order(StringComparer.Ordinal);

    foreach (var artifactDirectory in artifactDirectories)
    {
        var key = Path.GetFileName(artifactDirectory)[Report.ArtifactPrefix.Length..];

        if (key.Length > 0)
        {
            legs[key] = ReadTotals(artifactDirectory);
        }
    }

    return legs;
}

// A leg that failed still uploads its artifact (the upload step is `if: always()`), so an
// artifact directory with no readable report means "this leg produced no score" — which the
// report must show rather than silently omit.
static MutantTotals? ReadTotals(string artifactDirectory)
{
    var reports = Directory
        .EnumerateFiles(artifactDirectory, "mutation-report.json", SearchOption.AllDirectories)
        .Order(StringComparer.Ordinal)
        .ToArray();

    if (reports.Length == 0)
    {
        return null;
    }

    var detected = 0;
    var undetected = 0;

    foreach (var status in reports.SelectMany(ReadStatuses))
    {
        // Stryker's own formula: (Killed + Timeout) / (Killed + Timeout + Survived + NoCoverage).
        // Ignored, CompileError, RuntimeError and Pending are excluded from both halves, so an
        // unrecognised status must fall through into neither.
        switch (status)
        {
            case "Killed" or "Timeout":
                detected += 1;
                break;
            case "Survived" or "NoCoverage":
                undetected += 1;
                break;
        }
    }

    return new MutantTotals(detected, undetected);
}

static IReadOnlyList<string> ReadStatuses(string reportPath)
{
    using var stream = File.OpenRead(reportPath);
    using var document = JsonDocument.Parse(stream);

    if (!document.RootElement.TryGetProperty("files", out var files) || files.ValueKind != JsonValueKind.Object)
    {
        throw new InvalidOperationException($"{reportPath} has no 'files' object; it is not a Stryker JSON report.");
    }

    // Materialised because the JsonDocument is disposed when this method returns.
    var statuses = new List<string>();

    foreach (var file in files.EnumerateObject())
    {
        if (!file.Value.TryGetProperty("mutants", out var mutants) || mutants.ValueKind != JsonValueKind.Array)
        {
            continue;
        }

        var mutantStatuses = mutants
            .EnumerateArray()
            .Select(static mutant => mutant.TryGetProperty("status", out var status)
                && status.ValueKind == JsonValueKind.String
                    ? status.GetString()
                    : null)
            .Where(static status => status is not null);

        statuses.AddRange(mutantStatuses!);
    }

    return statuses;
}

static IReadOnlyDictionary<string, double?> ReadPreviousScores(string previousBodyFile)
{
    var empty = new Dictionary<string, double?>(StringComparer.Ordinal);

    if (!File.Exists(previousBodyFile))
    {
        return empty;
    }

    var body = File.ReadAllText(previousBodyFile);
    var start = body.IndexOf(Report.StateMarker, StringComparison.Ordinal);

    if (start < 0)
    {
        return empty;
    }

    start += Report.StateMarker.Length;
    var end = body.IndexOf("-->", start, StringComparison.Ordinal);

    if (end < 0)
    {
        return empty;
    }

    try
    {
        using var document = JsonDocument.Parse(body[start..end].Trim());
        var scores = new Dictionary<string, double?>(StringComparer.Ordinal);

        foreach (var entry in document.RootElement.EnumerateObject())
        {
            scores[entry.Name] = entry.Value.ValueKind == JsonValueKind.Number ? entry.Value.GetDouble() : null;
        }

        return scores;
    }
    catch (JsonException)
    {
        // A hand-edited or truncated state block must not fail the report. Treating it as a first
        // run reports every row as moved and rewrites the block correctly.
        Console.WriteLine("::warning::The tracking issue's state block could not be parsed; treating this as a first run.");
        return empty;
    }
}

// One row per target, plus one row per slice leg. The core target's slices partition its config's
// mutate globs exactly and disjointly, so summing their raw mutant counts reproduces the
// whole-target score — which is what makes the target row a valid CONTRIBUTING.md baseline.
// Summing the slices' *percentages* would not be, hence the counts rather than the scores.
static List<ReportRow> BuildRows(
    IReadOnlyDictionary<string, MutantTotals?> legs,
    IReadOnlyDictionary<string, double?> previous)
{
    var legKeys = legs.Keys
        .Concat(previous.Keys)
        .Distinct(StringComparer.Ordinal)
        .Order(StringComparer.Ordinal)
        .ToArray();

    var rows = new List<ReportRow>();

    foreach (var target in legKeys.Select(TargetOf).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))
    {
        var targetLegKeys = legKeys.Where(key => TargetOf(key) == target).ToArray();

        // A target's roll-up is only honest when every one of its legs reported. If a leg failed
        // or vanished, the sum would silently describe a smaller scope than the baseline it feeds.
        var totals = targetLegKeys
            .Select(key => legs.TryGetValue(key, out var legTotals) ? legTotals : null)
            .ToArray();

        var rolledUp = totals.Any(static total => total is null)
            ? null
            : new MutantTotals(totals.Sum(total => total!.Detected), totals.Sum(total => total!.Undetected));

        rows.Add(NewRow(target, rolledUp?.Score, previous));

        // An unsliced target's only leg is the target row itself; do not repeat it.
        foreach (var sliceKey in targetLegKeys.Where(key => key != target))
        {
            var slice = legs.TryGetValue(sliceKey, out var sliceTotals) ? sliceTotals : null;
            rows.Add(NewRow(sliceKey, slice?.Score, previous));
        }
    }

    return rows;
}

static ReportRow NewRow(string key, double? current, IReadOnlyDictionary<string, double?> previous)
    => new(
        Key: key,
        Current: current,
        Previous: previous.TryGetValue(key, out var was) ? was : null,
        WasKnown: previous.ContainsKey(key));

static string TargetOf(string legKey)
{
    var separator = legKey.IndexOf('-', StringComparison.Ordinal);

    return separator < 0 ? legKey : legKey[..separator];
}

static string RenderBody(IReadOnlyList<ReportRow> rows, string runDate)
{
    var builder = new StringBuilder();

    builder.AppendLine("<!-- Maintained by .github/workflows/mutation.yml. Edits to the table below are overwritten -->");
    builder.AppendLine("<!-- every Sunday; the state block at the bottom is what the next run compares against. -->");
    builder.AppendLine();
    builder.AppendLine("Mutation scores from the most recent scheduled `mutation.yml` run. A comment is posted on");
    builder.AppendLine("this issue only when a score changes, so a quiet inbox means the scores held.");
    builder.AppendLine();
    builder.AppendLine($"**Last run:** {runDate}");
    builder.AppendLine();
    builder.Append(RenderTable(rows));
    builder.AppendLine();
    builder.AppendLine("Scores use Stryker's own formula, `(Killed + Timeout) / (Killed + Timeout + Survived +");
    builder.AppendLine("NoCoverage)`. To refresh a baseline in `CONTRIBUTING.md`, copy a target row's **Score** and");
    builder.AppendLine("set its **Recorded** date to the run date above. Slice rows are detail only — they roll up");
    builder.AppendLine("into their target's row, which is the one `CONTRIBUTING.md` records.");
    builder.AppendLine();
    builder.AppendLine("This is a report, not a gate (#309 is deferred). GitHub disables scheduled workflows after");
    builder.AppendLine("60 days of repository inactivity, so if **Last run** is far in the past the schedule needs");
    builder.AppendLine("re-enabling from the Actions tab.");
    builder.AppendLine();
    builder.Append(Report.StateMarker);
    builder.Append(SerializeState(rows));
    builder.AppendLine(" -->");

    return builder.ToString();
}

// Written by hand rather than via JsonSerializer's reflection overloads, which the file-based
// app's trim/AOT analysis rejects.
static string SerializeState(IReadOnlyList<ReportRow> rows)
{
    using var buffer = new MemoryStream();

    using (var writer = new Utf8JsonWriter(buffer))
    {
        writer.WriteStartObject();

        foreach (var row in rows)
        {
            if (row.Current is null)
            {
                writer.WriteNull(row.Key);
            }
            else
            {
                writer.WriteNumber(row.Key, Math.Round(row.Current.Value, 2));
            }
        }

        writer.WriteEndObject();
    }

    return Encoding.UTF8.GetString(buffer.ToArray());
}

static string RenderComment(IReadOnlyList<ReportRow> rows, IReadOnlyList<ReportRow> changes, string runDate)
{
    var builder = new StringBuilder();

    builder.AppendLine($"### Mutation scores moved — run of {runDate}");
    builder.AppendLine();

    foreach (var change in changes)
    {
        builder.AppendLine($"- {DescribeChange(change)}");
    }

    builder.AppendLine();
    builder.Append(RenderTable(rows));

    return builder.ToString();
}

static string DescribeChange(ReportRow row) => (row.Current, row.Previous, row.WasKnown) switch
{
    (null, _, false) => $"**{row.Key}** — new row, but it reported no score.",
    (not null, _, false) => $"**{row.Key}** — new row, first score {FormatScore(row.Current)}.",
    (null, null, true) => $"**{row.Key}** — still reporting no score.",
    (null, not null, true) => $"**{row.Key}** — no score (was {FormatScore(row.Previous)}); a leg likely failed.",
    (not null, null, true) => $"**{row.Key}** — reporting again at {FormatScore(row.Current)} after a run with no score.",
    _ => $"**{row.Key}** — {FormatScore(row.Previous)} → {FormatScore(row.Current)} ({FormatDelta(row.Delta)}).",
};

static string RenderTable(IReadOnlyList<ReportRow> rows)
{
    var builder = new StringBuilder();

    builder.AppendLine("| Row | Score | Previous | Delta |");
    builder.AppendLine("|---|---:|---:|---:|");

    foreach (var row in rows)
    {
        // Slice rows are indented so a target and its detail read apart at a glance.
        var label = TargetOf(row.Key) == row.Key ? $"`{row.Key}`" : $"&nbsp;&nbsp;↳ `{row.Key}`";
        var score = row.Current is null ? FormatScore(row.Current) : $"**{FormatScore(row.Current)}**";

        var previous = row.WasKnown ? FormatScore(row.Previous) : "not recorded";

        builder.AppendLine($"| {label} | {score} | {previous} | {FormatDelta(row.Delta)} |");
    }

    return builder.ToString();
}

static string FormatScore(double? value)
    => value is null ? "no score" : value.Value.ToString("F2", CultureInfo.InvariantCulture) + " %";

static string FormatDelta(double? value)
    => value is null
        ? "n/a"
        : value.Value.ToString("+0.00;-0.00;0.00", CultureInfo.InvariantCulture) + " pp";

static void WriteOutput(string name, string value)
{
    var outputPath = Environment.GetEnvironmentVariable("GITHUB_OUTPUT");

    if (!string.IsNullOrWhiteSpace(outputPath))
    {
        File.AppendAllText(outputPath, $"{name}={value}{Environment.NewLine}");
    }
}

static int Fail(string message)
{
    Console.WriteLine($"::error::{message}");
    Console.Error.WriteLine(message);
    return 1;
}

internal static class Report
{
    // The artifact name mutation.yml uploads each leg under.
    public const string ArtifactPrefix = "mutation-report-";

    // Opens the machine-readable block in the tracking issue body that carries the previous run's
    // scores. Invisible when GitHub renders the body, so the issue stays readable.
    public const string StateMarker = "<!-- mutation-scores: ";
}

internal sealed record MutantTotals(int Detected, int Undetected)
{
    public double? Score => Detected + Undetected == 0 ? null : Detected / (double)(Detected + Undetected) * 100;
}

internal sealed record ReportRow(string Key, double? Current, double? Previous, bool WasKnown)
{
    // Scores are compared at the precision the report renders them, so float noise below the
    // second decimal never fires a "score moved" comment.
    public bool HasMoved => !WasKnown
        || (Current is null) != (Previous is null)
        || (Current is not null && Previous is not null
            && Math.Round(Current.Value, 2) != Math.Round(Previous.Value, 2));

    public double? Delta => Current is null || Previous is null ? null : Current.Value - Previous.Value;
}
