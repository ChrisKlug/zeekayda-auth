using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace ZeeKayDa.Auth.Analyzers;

/// <summary>
/// Catches non-constant string arguments passed to <c>Log*</c> methods inside <c>ZeeKayDa.*</c>
/// namespaces, and non-constant <c>messageTemplate</c> arguments passed to
/// <see cref="StartupVerificationContext.AddWarning"/>. The message template must be a
/// compile-time constant so that <c>SecretSanitizingLogger</c> can inspect the template and its
/// structured arguments — a non-constant string (interpolated, concatenated with a variable, or a
/// local variable) is already fully expanded and cannot be redacted. <c>AddWarning</c> needs its
/// own symbol-based check rather than the <c>Log*</c>-name-plus-<c>ILogger</c>-receiver heuristic:
/// it is not itself a <c>Log*</c> call, and its first parameter (<c>code</c>) is also a string, so
/// the "first string argument is the template" rule the <c>Log*</c> path relies on would pick the
/// wrong argument.
/// Diagnostic ID: ZEEKAYDA0002, category: LogHygiene, severity: Error.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class InterpolatedStringLogAnalyzer : DiagnosticAnalyzer
{
    /// <summary>Diagnostic ID emitted when a non-constant string is passed as a message template.</summary>
    public const string DiagnosticId = "ZEEKAYDA0002";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "Non-constant string passed as a message template",
        messageFormat: "Message templates must be compile-time constant strings; use a string literal and pass values as structured-logging arguments",
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
        if (!IsInZeeKayDaNamespace(invocation)) return;

        var methodName = memberAccess.Name.Identifier.Text;

        if (methodName.StartsWith("Log", System.StringComparison.Ordinal))
        {
            AnalyzeLogInvocation(context, invocation, memberAccess);
            return;
        }

        if (methodName == "AddWarning")
            AnalyzeAddWarningInvocation(context, invocation);
    }

    private static void AnalyzeLogInvocation(
        SyntaxNodeAnalysisContext context, InvocationExpressionSyntax invocation, MemberAccessExpressionSyntax memberAccess)
    {
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

    // Unlike Log*, AddWarning is identified by symbol (containing type + name), not by a
    // name-prefix-plus-receiver-type heuristic, and its template argument is found via the
    // bound IInvocationOperation's already-resolved parameter mapping — not by re-deriving
    // positional/named argument order from syntax — because that re-derivation previously got the
    // C# named-argument rules wrong for a leading named argument followed by a positional one
    // (e.g. `AddWarning(code: "x", $"leaked {secret}")`), silently skipping the check.
    private static void AnalyzeAddWarningInvocation(SyntaxNodeAnalysisContext context, InvocationExpressionSyntax invocation)
    {
        if (context.SemanticModel.GetOperation(invocation) is not IInvocationOperation operation) return;

        var method = operation.TargetMethod;
        if (method.ContainingType is not { Name: "StartupVerificationContext" } containingType) return;
        if (containingType.ContainingNamespace?.ToDisplayString() != "ZeeKayDa.Auth") return;

        var templateArgument = operation.Arguments.FirstOrDefault(a => a.Parameter?.Name == "messageTemplate");
        if (templateArgument is null) return;

        if (!templateArgument.Value.ConstantValue.HasValue)
            context.ReportDiagnostic(Diagnostic.Create(Rule, templateArgument.Value.Syntax.GetLocation()));
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
        if (typeSymbol is null) return false;

        // Only exempt types that live in ZeeKayDa.Auth itself.
        // Friend assemblies (InternalsVisibleTo) can implement ISanitizingLogger<T> but must
        // not self-exempt — the exemption is reserved for the wrapper defined in this assembly.
        if (typeSymbol.ContainingAssembly?.Name != "ZeeKayDa.Auth") return false;

        // Primary: exempt the concrete sanitizing-logger wrapper by name.
        if (typeSymbol is INamedTypeSymbol { Name: "SecretSanitizingLogger", TypeParameters.Length: 1 })
            return true;

        // Fallback: exempt any other ISanitizingLogger<T> implementation defined in this assembly.
        return typeSymbol.AllInterfaces.Any(i =>
            i.Name == "ISanitizingLogger" &&
            i.TypeParameters.Length == 1 &&
            i.ContainingNamespace?.ToDisplayString() == "ZeeKayDa.Auth.Logging");
    }
}
