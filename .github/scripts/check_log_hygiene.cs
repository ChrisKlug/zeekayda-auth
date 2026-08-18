#:package Microsoft.CodeAnalysis.CSharp

// Roslyn/MSBuild-driven log-hygiene checker.
//
// Replaces the regex-based predecessor script, which enumerated four suppression
// *syntaxes* and could not converge (see issue #459 for the full history and the 12
// compile-verified bypass vectors found against the enumeration approach).
//
// This script reads *effective severity* per source file by asking MSBuild/Roslyn to
// resolve it, rather than pattern-matching the ways a suppression can be spelled:
//
//   Pass A — semantic log-call hygiene: walks Log*/BeginScope/LoggerMessage.Define*/
//            [LoggerMessage]/StartupVerificationContext.AddWarning call sites in a
//            references-free compilation (for constant folding only) and flags a
//            sensitive OAuth/OIDC name used as a structured-log placeholder.
//   Pass B — semantic in-source suppression justification: requires the structured
//            "// log-hygiene-ok: <reason> (#N)" comment on any #pragma, [SuppressMessage],
//            or bare pragma that touches ZEEKAYDA0001/ZEEKAYDA0002; hard-fails on any
//            DiagnosticSuppressor/SuppressionDescriptor naming either rule (no hatch).
//   Pass C — effective severity per project: asks MSBuild for the evaluated NoWarn,
//            RunAnalyzers, analyzer-reference, ruleset, and analyzer-config state and
//            asserts neither rule ID is downgraded below Error anywhere in that
//            resolution. No project-wide escape hatch exists for pass C — any
//            project-wide downgrade is a hard failure even with a comment.
//
// Coverage scope: every project listed under the "/src/" folder of ZeeKayDa.Auth.slnx,
// plus samples/**/*.csproj. This intentionally includes ZeeKayDa.Auth.Analyzers (added
// to the solution alongside this script) — it has no ILogger/AddWarning call sites
// today, so including it costs nothing, and excluding it would need a special case that
// would go untested until the day it grows one. tests/ is intentionally out of scope:
// test projects legitimately suppress these rules to assert analyzer behaviour, and test
// code does not ship.
//
// Usage: dotnet run check_log_hygiene.cs -- <repo-root>
// Exit codes: 0 pass, 1 violation(s) found, 2 usage/internal error.

using System.Diagnostics;
using System.Text.Json;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

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
        Console.Error.WriteLine("Usage: check_log_hygiene.cs <repo-root>");
        return 2;
    }

    var repoRoot = Path.GetFullPath(args[0]);
    var projectPaths = DiscoverProjects(repoRoot);

    var violations = new List<string>();

    foreach (var projectPath in projectPaths)
    {
        var evaluation = EvaluateProject(projectPath);
        var compilation = BuildCompilation(evaluation.CompileFiles);

        violations.AddRange(LogHygieneRules.RunPassA(compilation));
        violations.AddRange(LogHygieneRules.RunPassB(compilation));
        violations.AddRange(LogHygieneRules.RunPassC(projectPath, evaluation));
    }

    if (violations.Count > 0)
    {
        foreach (var violation in violations)
        {
            Console.Error.WriteLine(violation);
            Console.Error.WriteLine();
        }

        return Fail($"Log hygiene check failed with {violations.Count} violation(s) across {projectPaths.Count} project(s). See above for details.");
    }

    Console.WriteLine($"Log hygiene check passed ({projectPaths.Count} project(s) checked).");
    return 0;
}

// Reads every "/src/" <Project Path> entry from ZeeKayDa.Auth.slnx (reusing the XML
// approach discover_coverage_projects.cs uses for "/tests/"), then adds samples/**/*.csproj
// by glob. samples/ currently holds only .gitkeep, so this is a no-op today and starts
// covering samples the moment one lands.
static IReadOnlyList<string> DiscoverProjects(string repoRoot)
{
    var solutionPath = Path.Combine(repoRoot, "ZeeKayDa.Auth.slnx");

    if (!File.Exists(solutionPath))
    {
        throw new InvalidOperationException($"Solution file not found: {solutionPath}");
    }

    var root = XDocument.Load(solutionPath).Root
        ?? throw new InvalidOperationException($"{solutionPath} is not a valid solution document.");

    var srcProjects = root.Descendants("Project")
        .Select(element => element.Attribute("Path")?.Value)
        .Where(path => !string.IsNullOrWhiteSpace(path))
        .Cast<string>()
        .Where(static path => path.Replace('\\', '/').StartsWith("src/", StringComparison.Ordinal))
        .Select(path => Path.Combine(repoRoot, path.Replace('/', Path.DirectorySeparatorChar)))
        .ToArray();

    if (srcProjects.Length == 0)
    {
        throw new InvalidOperationException($"No src projects found under a /src/ folder in {solutionPath}");
    }

    var samplesDir = Path.Combine(repoRoot, "samples");
    var sampleProjects = Directory.Exists(samplesDir)
        ? Directory.EnumerateFiles(samplesDir, "*.csproj", SearchOption.AllDirectories)
        : [];

    var allProjects = srcProjects
        .Concat(sampleProjects)
        .OrderBy(static path => path, StringComparer.Ordinal)
        .ToArray();

    foreach (var project in allProjects)
    {
        if (!File.Exists(project))
        {
            throw new InvalidOperationException($"Project not found: {project}");
        }
    }

    return allProjects;
}

// One `dotnet msbuild` invocation per project, shared by pass A (Compile items, to build
// the syntax trees) and pass C (everything else). RunAnalyzers/RunAnalyzersDuringBuild
// come back as an EMPTY STRING (not "true") when unset in a project — the pass C check
// below must treat empty as "not disabled" and only fail on an explicit "false".
static ProjectEvaluation EvaluateProject(string projectPath)
{
    var startInfo = new ProcessStartInfo("dotnet")
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
    };
    startInfo.ArgumentList.Add("msbuild");
    startInfo.ArgumentList.Add(projectPath);
    startInfo.ArgumentList.Add("-t:Restore,ResolveReferences");
    startInfo.ArgumentList.Add("-getItem:Compile,EditorConfigFiles,Analyzer");
    startInfo.ArgumentList.Add("-getProperty:NoWarn,RunAnalyzers,RunAnalyzersDuringBuild,WarningsAsErrors,WarningsNotAsErrors,TreatWarningsAsErrors,CodeAnalysisRuleSet");

    using var process = Process.Start(startInfo)
        ?? throw new InvalidOperationException($"Failed to start 'dotnet msbuild' for {projectPath}");

    var stdout = process.StandardOutput.ReadToEnd();
    var stderr = process.StandardError.ReadToEnd();
    process.WaitForExit();

    if (process.ExitCode != 0)
    {
        throw new InvalidOperationException($"'dotnet msbuild' failed for {projectPath} (exit {process.ExitCode}):\n{stderr}\n{stdout}");
    }

    using var document = JsonDocument.Parse(stdout);
    var rootElement = document.RootElement;
    var properties = rootElement.GetProperty("Properties");
    var items = rootElement.GetProperty("Items");

    return new ProjectEvaluation(
        ProjectPath: projectPath,
        Properties: ReadProperties(properties),
        CompileFiles: ReadItemFullPaths(items, "Compile"),
        EditorConfigFiles: ReadItemFullPaths(items, "EditorConfigFiles"),
        AnalyzerFiles: ReadItemFullPaths(items, "Analyzer"));
}

static IReadOnlyDictionary<string, string> ReadProperties(JsonElement propertiesElement)
{
    var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    foreach (var property in propertiesElement.EnumerateObject())
    {
        result[property.Name] = property.Value.GetString() ?? string.Empty;
    }

    return result;
}

static string[] ReadItemFullPaths(JsonElement itemsElement, string itemName)
{
    if (!itemsElement.TryGetProperty(itemName, out var itemArray))
    {
        return [];
    }

    return itemArray.EnumerateArray()
        .Select(item => item.GetProperty("FullPath").GetString()
            ?? throw new InvalidOperationException($"{itemName} item is missing FullPath"))
        .ToArray();
}

// One references-free CSharpCompilation per project, over its Compile items. "References-free"
// means no ProjectReference/PackageReference metadata is loaded — only the runtime's own
// corlib, which is required for even basic constant folding (a bare literal or `const string`
// reference doesn't fold to a value without it). Compile errors from unresolved application
// types are expected and ignored; the compilation exists purely so the semantic model can fold
// constants, which resolves `const string` templates the old text-based grep could not.
static CSharpCompilation BuildCompilation(IReadOnlyList<string> compileFiles)
{
    var trees = compileFiles
        .Select(path => CSharpSyntaxTree.ParseText(File.ReadAllText(path), path: path))
        .ToArray();

    // Avoid Assembly.Location (IL3000: unreliable/empty under single-file publish) — this script
    // never publishes single-file, but the repo's TreatWarningsAsErrors would still fail the
    // build on the warning. RuntimeEnvironment.GetRuntimeDirectory() finds the same corlib.
    var corlibPath = Path.Combine(System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory(), "System.Private.CoreLib.dll");
    var corlibReference = MetadataReference.CreateFromFile(corlibPath);

    return CSharpCompilation.Create(
        "LogHygieneCheck",
        trees,
        [corlibReference],
        new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
}

static int Fail(string message)
{
    Console.WriteLine($"::error::{message}");
    Console.Error.WriteLine(message);
    return 1;
}

internal sealed record ProjectEvaluation(
    string ProjectPath,
    IReadOnlyDictionary<string, string> Properties,
    IReadOnlyList<string> CompileFiles,
    IReadOnlyList<string> EditorConfigFiles,
    IReadOnlyList<string> AnalyzerFiles);

/// <summary>
/// Sensitive OAuth/OIDC parameter names that must never appear as a structured-log
/// placeholder, per ADR 0007 §7's log-never list. Copied verbatim from the PATTERN list in
/// the now-deleted predecessor shell script — do not alter without a corresponding ADR 0007
/// amendment, matched case-insensitively as before.
/// </summary>
internal static class SensitiveLogNames
{
    public static readonly string[] Names =
    [
        "client_secret",
        "code_verifier",
        "Authorization",
        "access_token",
        "refresh_token",
        "id_token",
        "client_assertion",
        "assertion",
        "device_code",
        "subject_token",
        "actor_token",
        "password",
        "code",
        "DPoP",
    ];
}

/// <summary>
/// Reads the "// log-hygiene-ok: &lt;reason&gt; (#N)" justification format from syntax
/// trivia. Kept as the single source of truth for the format so pass A and pass B validate
/// it identically: a non-empty reason and a parenthesised issue/PR number are required; the
/// bare form "// log-hygiene-ok" is rejected.
/// </summary>
internal static partial class Justification
{
    private static readonly System.Text.RegularExpressions.Regex Pattern =
        new(@"^//\s*log-hygiene-ok:\s+\S.*\(#\d+\)\s*$", System.Text.RegularExpressions.RegexOptions.Compiled);

    public static bool IsPresentOn(SyntaxNode anchor)
    {
        SyntaxNode container = anchor.FirstAncestorOrSelf<AttributeListSyntax>() as SyntaxNode
            ?? anchor.FirstAncestorOrSelf<StatementSyntax>() as SyntaxNode
            ?? anchor.FirstAncestorOrSelf<MemberDeclarationSyntax>() as SyntaxNode
            ?? anchor;

        return container.GetTrailingTrivia().Concat(anchor.GetLeadingTrivia())
            .Any(IsJustificationComment);
    }

    public static bool IsPresentOnPragma(PragmaWarningDirectiveTriviaSyntax pragma) =>
        pragma.DescendantTrivia(descendIntoTrivia: true).Any(IsJustificationComment);

    private static bool IsJustificationComment(SyntaxTrivia trivia) =>
        trivia.IsKind(SyntaxKind.SingleLineCommentTrivia) && Pattern.IsMatch(trivia.ToString().Trim());
}

internal static class LogHygieneRules
{
    private const string RuleId1 = "ZEEKAYDA0001";
    private const string RuleId2 = "ZEEKAYDA0002";

    private static readonly string[] RuleIds = [RuleId1, RuleId2];

    // ------------------------------------------------------------------
    // Pass A — semantic log-call hygiene (replaces the old script's check 1)
    // ------------------------------------------------------------------

    public static IEnumerable<string> RunPassA(CSharpCompilation compilation)
    {
        foreach (var tree in compilation.SyntaxTrees)
        {
            var model = compilation.GetSemanticModel(tree);
            var root = tree.GetRoot();

            foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
            {
                foreach (var violation in CheckInvocation(model, invocation))
                {
                    yield return violation;
                }
            }

            foreach (var attribute in root.DescendantNodes().OfType<AttributeSyntax>())
            {
                if (!IsNamed(attribute.Name, "LoggerMessage"))
                {
                    continue;
                }

                var messageArgument = attribute.ArgumentList?.Arguments
                    .FirstOrDefault(a => a.NameEquals?.Name.Identifier.Text == "Message");

                if (messageArgument is null)
                {
                    continue;
                }

                foreach (var violation in CheckTemplateExpression(model, messageArgument.Expression, attribute))
                {
                    yield return violation;
                }
            }
        }
    }

    private static IEnumerable<string> CheckInvocation(SemanticModel model, InvocationExpressionSyntax invocation)
    {
        var methodName = invocation.Expression switch
        {
            MemberAccessExpressionSyntax memberAccess => memberAccess.Name.Identifier.Text,
            MemberBindingExpressionSyntax memberBinding => memberBinding.Name.Identifier.Text,
            IdentifierNameSyntax identifierName => identifierName.Identifier.Text,
            _ => null,
        };

        if (methodName is null)
        {
            return [];
        }

        var isLogLike = methodName.StartsWith("Log", StringComparison.Ordinal) || methodName == "BeginScope";
        var isDefineLike = methodName.StartsWith("Define", StringComparison.Ordinal) && IsLoggerMessageQualifier(invocation.Expression);

        if (isLogLike || isDefineLike)
        {
            // Method identification is name/shape-based rather than symbol-based, since this
            // compilation carries no metadata for application types (see BuildCompilation).
            // Every string-constant argument is checked, not just "the template" argument,
            // since without symbol resolution there is no reliable way to know which argument
            // that is; this is a defence-in-depth pass, so over-checking is the safe direction.
            return invocation.ArgumentList.Arguments.SelectMany(argument =>
                CheckTemplateExpression(model, argument.Expression, invocation));
        }

        if (methodName == "AddWarning")
        {
            var templateArgument = FindNamedOrPositionalArgument(invocation.ArgumentList.Arguments, "messageTemplate", positionalIndex: 1);
            return templateArgument is null ? [] : CheckTemplateExpression(model, templateArgument, invocation);
        }

        return [];
    }

    private static bool IsLoggerMessageQualifier(ExpressionSyntax invocationExpression) =>
        invocationExpression is MemberAccessExpressionSyntax { Expression: IdentifierNameSyntax { Identifier.Text: "LoggerMessage" } }
            or MemberAccessExpressionSyntax { Expression: MemberAccessExpressionSyntax { Name.Identifier.Text: "LoggerMessage" } };

    private static ExpressionSyntax? FindNamedOrPositionalArgument(
        SeparatedSyntaxList<ArgumentSyntax> arguments, string name, int positionalIndex)
    {
        var named = arguments.FirstOrDefault(a => a.NameColon?.Name.Identifier.Text == name);
        if (named is not null)
        {
            return named.Expression;
        }

        var positional = arguments.Where(a => a.NameColon is null).ToArray();
        return positionalIndex < positional.Length ? positional[positionalIndex].Expression : null;
    }

    private static IEnumerable<string> CheckTemplateExpression(SemanticModel model, ExpressionSyntax expression, SyntaxNode reportAnchor)
    {
        var constant = model.GetConstantValue(expression);
        if (constant.Value is not string template)
        {
            yield break;
        }

        var sensitiveNames = ParsePlaceholderNames(template)
            .Where(placeholder => SensitiveLogNames.Names.Any(sensitive =>
                string.Equals(sensitive, placeholder, StringComparison.OrdinalIgnoreCase)))
            .ToArray();

        if (sensitiveNames.Length == 0)
        {
            yield break;
        }

        if (Justification.IsPresentOn(reportAnchor))
        {
            yield break;
        }

        var location = FormatLocation(expression);
        yield return
            $"""
            {location}: LOG HYGIENE FAILURE (ADR 0007 §7): message template contains sensitive placeholder(s) [{string.Join(", ", sensitiveNames)}]: "{template}"
            Sensitive parameter names must not appear as structured-log placeholders in any ZeeKayDa.Auth code.
            To suppress a specific line, append a structured suppression comment:
              // log-hygiene-ok: <non-empty reason> (#<issue-or-pr-number>)
            Example:
              // log-hygiene-ok: test fixture, never reaches production (#179)
            Both a non-empty reason and a parenthesised issue/PR number are required.
            The bare form "// log-hygiene-ok" is not accepted.
            """;
    }

    // Parses "{name}" and "{name:format}" placeholders, treating "{{" and "}}" as escaped
    // literal braces the way structured-logging templates do.
    private static IEnumerable<string> ParsePlaceholderNames(string template)
    {
        var i = 0;
        while (i < template.Length)
        {
            if (template[i] == '{' && i + 1 < template.Length && template[i + 1] == '{')
            {
                i += 2;
                continue;
            }

            if (template[i] == '}' && i + 1 < template.Length && template[i + 1] == '}')
            {
                i += 2;
                continue;
            }

            if (template[i] != '{')
            {
                i++;
                continue;
            }

            var close = template.IndexOf('}', i + 1);
            if (close < 0)
            {
                break;
            }

            var inner = template[(i + 1)..close];
            var colon = inner.IndexOf(':');
            yield return colon >= 0 ? inner[..colon] : inner;

            i = close + 1;
        }
    }

    // ------------------------------------------------------------------
    // Pass B — semantic in-source suppression justification (replaces checks 2 & 3)
    // ------------------------------------------------------------------

    public static IEnumerable<string> RunPassB(CSharpCompilation compilation)
    {
        foreach (var tree in compilation.SyntaxTrees)
        {
            var model = compilation.GetSemanticModel(tree);
            var root = tree.GetRoot();

            foreach (var pragma in root.DescendantNodes(descendIntoTrivia: true).OfType<PragmaWarningDirectiveTriviaSyntax>())
            {
                foreach (var violation in CheckPragma(pragma))
                {
                    yield return violation;
                }
            }

            foreach (var attribute in root.DescendantNodes().OfType<AttributeSyntax>())
            {
                foreach (var violation in CheckSuppressMessageAttribute(model, attribute))
                {
                    yield return violation;
                }
            }

            foreach (var classDeclaration in root.DescendantNodes().OfType<ClassDeclarationSyntax>())
            {
                foreach (var violation in CheckDiagnosticSuppressorSubclass(classDeclaration))
                {
                    yield return violation;
                }
            }

            foreach (var creation in root.DescendantNodes().OfType<BaseObjectCreationExpressionSyntax>())
            {
                foreach (var violation in CheckSuppressionDescriptor(model, creation))
                {
                    yield return violation;
                }
            }
        }
    }

    private static IEnumerable<string> CheckPragma(PragmaWarningDirectiveTriviaSyntax pragma)
    {
        if (!pragma.DisableOrRestoreKeyword.IsKind(SyntaxKind.DisableKeyword))
        {
            yield break;
        }

        var isBare = pragma.ErrorCodes.Count == 0;
        var namesRule = pragma.ErrorCodes.Any(code => RuleIds.Contains(code.ToString(), StringComparer.OrdinalIgnoreCase));

        if (!isBare && !namesRule)
        {
            yield break;
        }

        if (Justification.IsPresentOnPragma(pragma))
        {
            yield break;
        }

        var location = FormatLocation(pragma);
        var subject = isBare
            ? "a bare #pragma warning disable (suppresses every diagnostic for the rest of the file, including ZEEKAYDA0001/ZEEKAYDA0002)"
            : "a #pragma warning disable for ZEEKAYDA0001/ZEEKAYDA0002";

        yield return
            $"""
            {location}: LOG HYGIENE FAILURE: {subject} must
            carry a structured suppression comment on the same line:
              // log-hygiene-ok: <non-empty reason> (#<issue-or-pr-number>)
            """;
    }

    private static IEnumerable<string> CheckSuppressMessageAttribute(SemanticModel model, AttributeSyntax attribute)
    {
        if (!IsNamed(attribute.Name, "SuppressMessage") || attribute.ArgumentList is null)
        {
            yield break;
        }

        var checkIdArgument = FindAttributeArgument(attribute.ArgumentList.Arguments, "checkId", positionalIndex: 1);
        if (checkIdArgument is null)
        {
            yield break;
        }

        var constant = model.GetConstantValue(checkIdArgument.Expression);
        if (constant.Value is not string checkId || !RuleIds.Contains(checkId, StringComparer.OrdinalIgnoreCase))
        {
            yield break;
        }

        if (Justification.IsPresentOn(attribute))
        {
            yield break;
        }

        var location = FormatLocation(attribute);
        yield return
            $"""
            {location}: LOG HYGIENE FAILURE: a [SuppressMessage] attribute for {checkId} must
            carry a structured suppression comment on the same line:
              // log-hygiene-ok: <non-empty reason> (#<issue-or-pr-number>)
            """;
    }

    private static AttributeArgumentSyntax? FindAttributeArgument(
        SeparatedSyntaxList<AttributeArgumentSyntax> arguments, string name, int positionalIndex)
    {
        var named = arguments.FirstOrDefault(a => a.NameColon?.Name.Identifier.Text == name);
        if (named is not null)
        {
            return named;
        }

        var positional = arguments.Where(a => a.NameColon is null).ToArray();
        return positionalIndex < positional.Length ? positional[positionalIndex] : null;
    }

    // A custom DiagnosticSuppressor is a hard failure with no justification-comment escape
    // hatch: unlike a #pragma or [SuppressMessage] at a call site, it is a standing,
    // programmatic suppression that no single-line comment can scope or make reviewable.
    private static IEnumerable<string> CheckDiagnosticSuppressorSubclass(ClassDeclarationSyntax classDeclaration)
    {
        var derivesFromSuppressor = classDeclaration.BaseList?.Types
            .Any(baseType => IsNamed(baseType.Type, "DiagnosticSuppressor")) ?? false;

        if (!derivesFromSuppressor)
        {
            yield break;
        }

        var location = FormatLocation(classDeclaration);
        yield return
            $"""
            {location}: LOG HYGIENE FAILURE: a DiagnosticSuppressor subclass was found. Programmatic
            suppression of any diagnostic is not a sanctioned route for ZEEKAYDA0001/ZEEKAYDA0002 and
            has no justification-comment escape hatch; remove it or suppress narrowly at the call site
            with a justified #pragma/[SuppressMessage] instead.
            """;
    }

    private static IEnumerable<string> CheckSuppressionDescriptor(SemanticModel model, BaseObjectCreationExpressionSyntax creation)
    {
        var isSuppressionDescriptor = creation switch
        {
            ObjectCreationExpressionSyntax { Type: { } type } => IsNamed(type, "SuppressionDescriptor"),
            ImplicitObjectCreationExpressionSyntax => true,
            _ => false,
        };

        if (!isSuppressionDescriptor || creation.ArgumentList is null)
        {
            yield break;
        }

        var suppressedIdArgument = FindNamedOrPositionalArgument(creation.ArgumentList.Arguments, "suppressedDiagnosticId", positionalIndex: 1);
        if (suppressedIdArgument is null)
        {
            yield break;
        }

        var constant = model.GetConstantValue(suppressedIdArgument);
        if (constant.Value is not string suppressedId || !RuleIds.Contains(suppressedId, StringComparer.OrdinalIgnoreCase))
        {
            yield break;
        }

        var location = FormatLocation(creation);
        yield return
            $"""
            {location}: LOG HYGIENE FAILURE: a SuppressionDescriptor naming {suppressedId} was found. This is
            not a sanctioned suppression route and has no justification-comment escape hatch; remove it or
            suppress narrowly at the call site with a justified #pragma/[SuppressMessage] instead.
            """;
    }

    // ------------------------------------------------------------------
    // Pass C — effective severity per project (replaces checks 4 & 5)
    // ------------------------------------------------------------------

    public static IEnumerable<string> RunPassC(string projectPath, ProjectEvaluation evaluation)
    {
        foreach (var violation in CheckAnalyzerPresent(projectPath, evaluation))
        {
            yield return violation;
        }

        foreach (var violation in CheckRunAnalyzersEnabled(projectPath, evaluation))
        {
            yield return violation;
        }

        foreach (var violation in CheckNoWarnAndWarningsNotAsErrors(projectPath, evaluation))
        {
            yield return violation;
        }

        // Deliberately not caught here: a malformed .editorconfig/.globalconfig is an internal
        // error (surfaced via Fail at the top level), not a log-hygiene violation to report
        // alongside the rest — the check cannot make any severity assertion without it.
        var configSet = BuildAnalyzerConfigSet(evaluation.EditorConfigFiles);

        {
            foreach (var violation in CheckAnalyzerConfigSeverity(projectPath, evaluation, configSet))
            {
                yield return violation;
            }
        }

        foreach (var violation in CheckRuleset(projectPath, evaluation))
        {
            yield return violation;
        }
    }

    // ZeeKayDa.Auth.Analyzers is in scope for passes A/B (it's a "/src/" project), but it cannot
    // reference its own build output as an Analyzer item — that would be circular — so it can
    // never satisfy this specific assertion. This was found empirically (not assumed) while
    // verifying the checker against the clean tree after adding the project to the .slnx: every
    // other pass-C assertion still applies to it (RunAnalyzers, NoWarn, severity, ruleset), since
    // those stay meaningful if the project's build wiring changes; only "is the analyzer DLL
    // present" is inherently inapplicable to the analyzer itself.
    private static IEnumerable<string> CheckAnalyzerPresent(string projectPath, ProjectEvaluation evaluation)
    {
        if (string.Equals(Path.GetFileName(projectPath), "ZeeKayDa.Auth.Analyzers.csproj", StringComparison.OrdinalIgnoreCase))
        {
            yield break;
        }

        var hasAnalyzer = evaluation.AnalyzerFiles.Any(path =>
            string.Equals(Path.GetFileName(path), "ZeeKayDa.Auth.Analyzers.dll", StringComparison.OrdinalIgnoreCase));

        if (hasAnalyzer)
        {
            yield break;
        }

        yield return
            $"""
            {projectPath}: LOG HYGIENE FAILURE: ZeeKayDa.Auth.Analyzers.dll is not present in the
            resolved Analyzer items for this project — the ZEEKAYDA0001/ZEEKAYDA0002 analyzers are not
            running. This is a project-wide gap and has no justification-comment escape hatch.
            """;
    }

    private static IEnumerable<string> CheckRunAnalyzersEnabled(string projectPath, ProjectEvaluation evaluation)
    {
        foreach (var property in new[] { "RunAnalyzers", "RunAnalyzersDuringBuild" })
        {
            // Empty/unset means "not disabled" (the MSBuild default is true); only an explicit
            // case-insensitive "false" downgrades this project's analyzer coverage.
            if (evaluation.Properties.TryGetValue(property, out var value)
                && string.Equals(value.Trim(), "false", StringComparison.OrdinalIgnoreCase))
            {
                yield return
                    $"""
                    {projectPath}: LOG HYGIENE FAILURE: {property} is set to false, disabling all analyzers
                    including ZEEKAYDA0001/ZEEKAYDA0002. Project-wide analyzer suppression is not a
                    sanctioned route and has no justification-comment escape hatch.
                    """;
            }
        }
    }

    private static IEnumerable<string> CheckNoWarnAndWarningsNotAsErrors(string projectPath, ProjectEvaluation evaluation)
    {
        foreach (var property in new[] { "NoWarn", "WarningsNotAsErrors" })
        {
            if (!evaluation.Properties.TryGetValue(property, out var value) || string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            var entries = value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var matched = entries.Where(entry => RuleIds.Contains(entry, StringComparer.OrdinalIgnoreCase)).ToArray();

            foreach (var ruleId in matched)
            {
                yield return
                    $"""
                    {projectPath}: LOG HYGIENE FAILURE: {property} suppresses {ruleId} project-wide. Project-wide
                    suppression is not a sanctioned route — even with a justification comment; use a
                    narrowly-scoped, justified #pragma/[SuppressMessage] at the call site instead.
                    """;
            }
        }
    }

    private static AnalyzerConfigSet BuildAnalyzerConfigSet(IReadOnlyList<string> editorConfigFiles)
    {
        var configs = editorConfigFiles
            .Select(path => AnalyzerConfig.Parse(SourceText.From(File.ReadAllText(path)), path))
            .ToList();

        return AnalyzerConfigSet.Create(configs);
    }

    private static IEnumerable<string> CheckAnalyzerConfigSeverity(
        string projectPath, ProjectEvaluation evaluation, AnalyzerConfigSet configSet)
    {
        // .globalconfig files self-identify via is_global and are folded into GlobalConfigOptions
        // by AnalyzerConfigSet rather than into any single source path's per-path options, so they
        // need their own check alongside the per-Compile-item one below.
        foreach (var violation in CheckOptionsResult(projectPath, "global config", configSet.GlobalConfigOptions))
        {
            yield return violation;
        }

        foreach (var compileFile in evaluation.CompileFiles)
        {
            var options = configSet.GetOptionsForSourcePath(compileFile);
            foreach (var violation in CheckOptionsResult(compileFile, "source file", options))
            {
                yield return violation;
            }
        }
    }

    private static IEnumerable<string> CheckOptionsResult(string subjectPath, string subjectKind, AnalyzerConfigOptionsResult options)
    {
        foreach (var ruleId in RuleIds)
        {
            // AnalyzerConfig lowercases every key, so this lookup is case-insensitive by
            // construction — the old script's case-sensitivity gap on severity values disappears.
            if (options.TreeOptions.TryGetValue(ruleId.ToLowerInvariant(), out var severity)
                && severity != ReportDiagnostic.Error && severity != ReportDiagnostic.Default)
            {
                yield return
                    $"""
                    {subjectPath}: LOG HYGIENE FAILURE: {subjectKind} resolves {ruleId} to severity '{severity}',
                    below Error. Project-wide/config-based severity downgrades are not a sanctioned route and
                    have no justification-comment escape hatch.
                    """;
            }
        }

        foreach (var key in new[] { "dotnet_analyzer_diagnostic.category-loghygiene.severity", "dotnet_analyzer_diagnostic.severity" })
        {
            if (options.AnalyzerOptions.TryGetValue(key, out var value)
                && !string.Equals(value, "error", StringComparison.OrdinalIgnoreCase))
            {
                yield return
                    $"""
                    {subjectPath}: LOG HYGIENE FAILURE: {subjectKind} sets {key} = {value}, which downgrades
                    ZEEKAYDA0001/ZEEKAYDA0002 (and every other analyzer diagnostic in that bucket) below Error.
                    This is not a sanctioned route and has no justification-comment escape hatch.
                    """;
            }
        }
    }

    private static IEnumerable<string> CheckRuleset(string projectPath, ProjectEvaluation evaluation)
    {
        if (!evaluation.Properties.TryGetValue("CodeAnalysisRuleSet", out var rulesetPath) || string.IsNullOrWhiteSpace(rulesetPath))
        {
            yield break;
        }

        var resolvedPath = Path.IsPathRooted(rulesetPath)
            ? rulesetPath
            : Path.Combine(Path.GetDirectoryName(projectPath)!, rulesetPath);

        if (!File.Exists(resolvedPath))
        {
            yield return $"{projectPath}: LOG HYGIENE FAILURE: CodeAnalysisRuleSet is set to '{rulesetPath}' but the file was not found at {resolvedPath}.";
            yield break;
        }

        var rulesetRoot = XDocument.Load(resolvedPath).Root
            ?? throw new InvalidOperationException($"{resolvedPath} is not a valid ruleset document.");

        foreach (var rule in rulesetRoot.Descendants("Rule"))
        {
            var id = rule.Attribute("Id")?.Value;
            var action = rule.Attribute("Action")?.Value;

            if (id is null || action is null || !RuleIds.Contains(id, StringComparer.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!string.Equals(action, "Error", StringComparison.OrdinalIgnoreCase))
            {
                yield return
                    $"""
                    {resolvedPath}: LOG HYGIENE FAILURE: ruleset action for {id} is '{action}', not Error.
                    This is not a sanctioned route and has no justification-comment escape hatch.
                    """;
            }
        }
    }

    // ------------------------------------------------------------------
    // Shared helpers
    // ------------------------------------------------------------------

    private static bool IsNamed(ExpressionSyntax name, string simpleName)
    {
        var text = name.ToString();
        var lastSegment = text.Contains('.') ? text[(text.LastIndexOf('.') + 1)..] : text;
        return lastSegment == simpleName || lastSegment == simpleName + "Attribute";
    }

    private static string FormatLocation(SyntaxNode node)
    {
        var lineSpan = node.SyntaxTree.GetLineSpan(node.Span);
        return $"{node.SyntaxTree.FilePath}:{lineSpan.StartLinePosition.Line + 1}";
    }
}
