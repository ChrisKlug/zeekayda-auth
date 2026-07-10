using System.Text.RegularExpressions;
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
    if (args.Length != 1)
    {
        Console.Error.WriteLine("Usage: discover_coverage_projects.cs <repo-root>");
        return 2;
    }

    var repoRoot = args[0];
    var solutionPath = Path.Combine(repoRoot, "ZeeKayDa.Auth.slnx");

    // Discovery is scoped to what ZeeKayDa.Auth.slnx actually lists (not a bare tests/*/ glob) so
    // it stays in lockstep with what the job's own `dotnet restore`/`dotnet build` steps put on
    // disk. A test project that isn't part of the canonical solution (e.g. the analyzers package,
    // which ships and is tested independently of it) is never a coverage-regression candidate.
    var packages = ReadTestProjectPaths(solutionPath)
        .Select(DerivePackageName)
        .Where(name => !IsOsRestricted(repoRoot, name))
        .OrderBy(static name => name, StringComparer.Ordinal)
        .ToArray();

    if (packages.Length == 0)
    {
        throw new InvalidOperationException($"No coverage-eligible test projects discovered in {solutionPath}");
    }

    foreach (var package in packages)
    {
        Console.WriteLine(package);
    }

    return 0;
}

static IReadOnlyList<string> ReadTestProjectPaths(string solutionPath)
{
    if (!File.Exists(solutionPath))
    {
        throw new InvalidOperationException($"Solution file not found: {solutionPath}");
    }

    var root = XDocument.Load(solutionPath).Root
        ?? throw new InvalidOperationException($"{solutionPath} is not a valid solution document.");

    var paths = root.Descendants("Project")
        .Select(element => element.Attribute("Path")?.Value)
        .Where(path => !string.IsNullOrWhiteSpace(path))
        .Cast<string>()
        .Where(static path => path.Replace('\\', '/').StartsWith("tests/", StringComparison.Ordinal))
        .ToArray();

    if (paths.Length == 0)
    {
        throw new InvalidOperationException($"No test projects found under a /tests/ folder in {solutionPath}");
    }

    return paths;
}

static string DerivePackageName(string testProjectPath)
{
    // Convention (repo-wide): tests/<PackageName>.Tests/<PackageName>.Tests.csproj pairs with
    // production package <PackageName>, whose coverage Include filter is always "[<PackageName>]*".
    var projectFileName = Path.GetFileNameWithoutExtension(testProjectPath.Replace('\\', '/'));

    if (!projectFileName.EndsWith(".Tests", StringComparison.Ordinal))
    {
        throw new InvalidOperationException(
            $"Test project '{testProjectPath}' does not follow the '<PackageName>.Tests' naming convention.");
    }

    return projectFileName[..^".Tests".Length];
}

static bool IsOsRestricted(string repoRoot, string packageName)
{
    var csprojPath = Path.Combine(repoRoot, "src", packageName, $"{packageName}.csproj");

    if (!File.Exists(csprojPath))
    {
        throw new InvalidOperationException(
            $"No paired production project found for test package '{packageName}' (expected {csprojPath}).");
    }

    var root = XDocument.Load(csprojPath).Root
        ?? throw new InvalidOperationException($"{csprojPath} is not a valid project document.");

    var targetFrameworks = (root.Descendants("TargetFrameworks").FirstOrDefault()?.Value
            ?? root.Descendants("TargetFramework").FirstOrDefault()?.Value)
        ?.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        ?? throw new InvalidOperationException($"{csprojPath} declares no TargetFramework(s).");

    // coverage-regression runs as a single ubuntu-latest job (no per-OS .slnf selection like
    // build-and-test), so a package is excluded only if every one of its TFMs is platform-specific
    // (e.g. net10.0-windows) and none can actually run here. A cross-platform TFM anywhere in the
    // list (e.g. net10.0) means it stays eligible.
    return targetFrameworks.All(static tfm => Regex.IsMatch(tfm, @"^net[\d.]+-\w+"));
}

static int Fail(string message)
{
    Console.WriteLine($"::error::{message}");
    Console.Error.WriteLine(message);
    return 1;
}
