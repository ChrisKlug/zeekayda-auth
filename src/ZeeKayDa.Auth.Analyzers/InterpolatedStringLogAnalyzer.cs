using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace ZeeKayDa.Auth.Analyzers;

/// <summary>
/// Catches interpolated string arguments that contain sensitive identifiers being passed to
/// <c>Log*</c> methods inside <c>ZeeKayDa.*</c> namespaces. At runtime a plain interpolated
/// string is fully expanded before the logger ever sees it, so the
/// <c>SecretSanitizingLogger</c> wrapper cannot redact the value.
/// Diagnostic ID: ZEEKAYDA0002, category: LogHygiene, severity: Error.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class InterpolatedStringLogAnalyzer : DiagnosticAnalyzer
{
    /// <summary>Diagnostic ID emitted when a sensitive interpolated string is passed to a <c>Log*</c> method.</summary>
    public const string DiagnosticId = "ZEEKAYDA0002";

    /// <summary>
    /// Identifiers (matched case-insensitively as substrings) that indicate a value is sensitive
    /// and must not appear inside an interpolated string passed to a logging method.
    /// </summary>
    public static readonly ImmutableHashSet<string> SensitiveKeywords =
        ImmutableHashSet.Create(
            StringComparer.OrdinalIgnoreCase,
            "secret",
            "password",
            "token",
            "key",
            "code_verifier",
            "client_assertion",
            "device_code",
            "subject_token",
            "actor_token",
            "dpop",
            "authorization");

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "Interpolated string with sensitive identifier passed to Log* method",
        messageFormat: "Do not pass interpolated strings containing sensitive identifiers to Log* methods; use structured logging instead",
        category: "LogHygiene",
        defaultSeverity: DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    /// <inheritdoc/>
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(Rule);

    /// <inheritdoc/>
    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        var invocation = (InvocationExpressionSyntax)context.Node;

        if (!IsLogMethodCall(invocation)) return;
        if (!IsInZeeKayDaNamespace(invocation)) return;

        foreach (var argument in invocation.ArgumentList.Arguments.Where(
                     argument => argument.Expression is InterpolatedStringExpressionSyntax interpolated
                                 && ContainsSensitiveIdentifier(interpolated)))
        {
            context.ReportDiagnostic(Diagnostic.Create(Rule, argument.GetLocation()));
        }
    }

    private static bool IsLogMethodCall(InvocationExpressionSyntax invocation)
    {
        var methodName = invocation.Expression switch
        {
            MemberAccessExpressionSyntax memberAccess => memberAccess.Name.Identifier.Text,
            IdentifierNameSyntax identifier => identifier.Identifier.Text,
            _ => null
        };

        return methodName is not null
            && methodName.StartsWith("Log", System.StringComparison.Ordinal);
    }

    private static bool IsInZeeKayDaNamespace(SyntaxNode node)
    {
        var parts = new System.Collections.Generic.List<string>();
        foreach (var ns in node.Ancestors().OfType<BaseNamespaceDeclarationSyntax>())
            parts.Insert(0, ns.Name.ToString());

        if (parts.Count == 0) return false;
        var fullNamespace = string.Join(".", parts);
        return fullNamespace.StartsWith("ZeeKayDa.", System.StringComparison.Ordinal)
            && !fullNamespace.StartsWith("ZeeKayDa.Auth.Analyzers", System.StringComparison.Ordinal);
    }

    private static bool ContainsSensitiveIdentifier(InterpolatedStringExpressionSyntax interpolated)
    {
        foreach (var content in interpolated.Contents)
        {
            if (content is InterpolatedStringTextSyntax literal)
            {
                if (ContainsSensitiveKeyword(literal.TextToken.ValueText))
                    return true;
            }
            else if (content is InterpolationSyntax hole)
            {
                foreach (var token in hole.Expression.DescendantTokens().Where(t => t.IsKind(SyntaxKind.IdentifierToken)))
                {
                    if (ContainsSensitiveKeyword(token.ValueText))
                    {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private static bool ContainsSensitiveKeyword(string text)
    {
        foreach (var keyword in SensitiveKeywords)
        {
            if (text.IndexOf(keyword, System.StringComparison.OrdinalIgnoreCase) >= 0)
                return true;
        }

        return false;
    }
}
