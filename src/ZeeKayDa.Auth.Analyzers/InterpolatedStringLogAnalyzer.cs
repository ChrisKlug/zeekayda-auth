using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace ZeeKayDa.Auth.Analyzers;

/// <summary>
/// Catches non-constant string arguments passed to <c>Log*</c> methods inside <c>ZeeKayDa.*</c>
/// namespaces. The message template must be a compile-time constant so that
/// <c>SecretSanitizingLogger</c> can inspect the template and its structured arguments — a
/// non-constant string (interpolated, concatenated with a variable, or a local variable) is
/// already fully expanded and cannot be redacted.
/// Diagnostic ID: ZEEKAYDA0002, category: LogHygiene, severity: Error.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class InterpolatedStringLogAnalyzer : DiagnosticAnalyzer
{
    /// <summary>Diagnostic ID emitted when a non-constant string is passed to a <c>Log*</c> method.</summary>
    public const string DiagnosticId = "ZEEKAYDA0002";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "Non-constant string passed as Log* message template",
        messageFormat: "Log* message templates must be compile-time constant strings; use a string literal and pass values as structured-logging arguments",
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

        if (invocation.Expression is not MemberAccessExpressionSyntax memberAccess) return;

        var methodName = memberAccess.Name.Identifier.Text;
        if (!methodName.StartsWith("Log", System.StringComparison.Ordinal)) return;

        if (!IsInZeeKayDaNamespace(invocation)) return;
        if (IsInLoggerImplementation(context, invocation)) return;

        var receiverType = context.SemanticModel.GetTypeInfo(memberAccess.Expression).Type;
        if (receiverType is null) return;

        if (!ImplementsILogger(receiverType)) return;

        // Only the message template (first string-typed argument) must be a constant.
        // Arguments that follow are structured-logging values and are intentionally dynamic.
        foreach (var argument in invocation.ArgumentList.Arguments)
        {
            var argType = context.SemanticModel.GetTypeInfo(argument.Expression).Type;
            if (argType?.SpecialType != SpecialType.System_String) continue;

            if (!context.SemanticModel.GetConstantValue(argument.Expression).HasValue)
                context.ReportDiagnostic(Diagnostic.Create(Rule, argument.GetLocation()));

            // Stop after the first string argument — it is the template.
            break;
        }
    }

    private static bool ImplementsILogger(ITypeSymbol type)
    {
        return IsNonGenericILogger(type)
            || type.AllInterfaces.Any(IsNonGenericILogger);
    }

    private static bool IsNonGenericILogger(ITypeSymbol type)
    {
        return type.Name == "ILogger"
            && type.ContainingNamespace?.ToDisplayString() == "Microsoft.Extensions.Logging"
            && type is INamedTypeSymbol named
            && named.TypeParameters.Length == 0;
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

    private static bool IsInLoggerImplementation(SyntaxNodeAnalysisContext context, SyntaxNode node)
    {
        var typeDecl = node.Ancestors().OfType<BaseTypeDeclarationSyntax>().FirstOrDefault();
        if (typeDecl is null) return false;

        var typeSymbol = context.SemanticModel.GetDeclaredSymbol(typeDecl);
        return typeSymbol?.AllInterfaces.Any(i =>
            i.Name == "ISanitizingLogger" &&
            i.TypeParameters.Length == 1 &&
            i.ContainingNamespace?.ToDisplayString() == "ZeeKayDa.Auth.Logging") ?? false;
    }
}
