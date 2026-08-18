using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace ZeeKayDa.Auth.Analyzers;

/// <summary>
/// Catches non-constant string arguments passed to <c>Log*</c>/<c>BeginScope</c> calls (instance,
/// conditional-access, or static extension-method form) inside <c>ZeeKayDa.*</c> namespaces, and
/// non-constant <c>messageTemplate</c> arguments passed to
/// <c>StartupVerificationContext.AddWarning</c> (qualified or unqualified). The message template must be a
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

        // Plain `logger.LogX(...)` uses MemberAccessExpressionSyntax; conditional-access
        // `logger?.LogX(...)` uses MemberBindingExpressionSyntax, whose receiver lives on the
        // enclosing ConditionalAccessExpressionSyntax rather than on the member node itself.
        ExpressionSyntax? receiverExpression;
        string methodName;
        switch (invocation.Expression)
        {
            case MemberAccessExpressionSyntax memberAccess:
                receiverExpression = memberAccess.Expression;
                methodName = memberAccess.Name.Identifier.Text;
                break;
            case MemberBindingExpressionSyntax memberBinding:
                receiverExpression = GetConditionalAccessReceiver(invocation);
                methodName = memberBinding.Name.Identifier.Text;
                break;
            case IdentifierNameSyntax identifierName:
                // Unqualified call with an implicit `this` receiver, e.g. AddWarning(...) called
                // from inside StartupVerificationContext itself. Only the AddWarning path below
                // can handle this — it matches by symbol and never needs a receiver expression;
                // Log*/BeginScope calls are never made unqualified against an implicit `this`.
                receiverExpression = null;
                methodName = identifierName.Identifier.Text;
                break;
            default:
                return;
        }

        if (!IsInZeeKayDaNamespace(invocation)) return;

        if (methodName.StartsWith("Log", System.StringComparison.Ordinal) || methodName == "BeginScope")
        {
            // Only this branch needs the resolved receiver; AddWarning is matched by symbol
            // (containing type + name) and never looks at it.
            if (receiverExpression is null) return;
            AnalyzeLogInvocation(context, invocation, receiverExpression);
            return;
        }

        if (methodName == "AddWarning")
            AnalyzeAddWarningInvocation(context, invocation);
    }

    // Walks up through the fluent chain (member accesses and invocations) that the target
    // invocation is the root of, to find the ConditionalAccessExpressionSyntax it ultimately
    // belongs to — not just an immediate `x?.Y(...)` parent. This matters for a chain like
    // `logger?.LogChain(...).LogChain(...)`, where the first call's direct parent is a
    // MemberAccessExpressionSyntax for the next link, not the ConditionalAccessExpressionSyntax
    // itself.
    private static ExpressionSyntax? GetConditionalAccessReceiver(InvocationExpressionSyntax invocation)
    {
        SyntaxNode current = invocation;
        while (true)
        {
            switch (current.Parent)
            {
                case ConditionalAccessExpressionSyntax { WhenNotNull: var whenNotNull } conditional
                    when whenNotNull == current:
                    return conditional.Expression;

                case MemberAccessExpressionSyntax memberAccess when memberAccess.Expression == current:
                    current = memberAccess;
                    continue;

                case InvocationExpressionSyntax outerInvocation when outerInvocation.Expression == current:
                    current = outerInvocation;
                    continue;

                default:
                    return null;
            }
        }
    }

    private static void AnalyzeLogInvocation(
        SyntaxNodeAnalysisContext context, InvocationExpressionSyntax invocation, ExpressionSyntax receiverExpression)
    {
        if (IsInLoggerImplementation(context, invocation)) return;

        var receiverType = ResolveLoggerReceiverType(context, invocation, receiverExpression);
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

    // `LoggerExtensions.LogInformation(logger, "...")` (static-method call form) names the
    // extension method's declaring type on the left of the dot — GetTypeInfo on that expression
    // resolves to the LoggerExtensions type itself, not the logger value, even though the call is
    // genuinely against an ILogger. In that shape the real receiver is the invocation's first
    // argument (the extension method's "this" parameter).
    private static ITypeSymbol? ResolveLoggerReceiverType(
        SyntaxNodeAnalysisContext context, InvocationExpressionSyntax invocation, ExpressionSyntax receiverExpression)
    {
        var receiverType = context.SemanticModel.GetTypeInfo(receiverExpression).Type;
        if (receiverType is not null && ImplementsILogger(receiverType)) return receiverType;

        if (context.SemanticModel.GetSymbolInfo(invocation).Symbol is IMethodSymbol { IsExtensionMethod: true } &&
            invocation.ArgumentList.Arguments.Count > 0)
        {
            return context.SemanticModel.GetTypeInfo(invocation.ArgumentList.Arguments[0].Expression).Type;
        }

        return receiverType;
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

        if (templateArgument.Value.ConstantValue.HasValue) return;
        if (IsForwardedMessageTemplateParameter(templateArgument.Value, containingType)) return;

        context.ReportDiagnostic(Diagnostic.Create(Rule, templateArgument.Value.Syntax.GetLocation()));
    }

    // StartupVerificationContext's own params-array overload forwards its non-constant
    // messageTemplate parameter, unchanged, to the LogLevel overload — that call site is not a
    // new template being constructed, just the already-validated parameter passing through, so
    // it must not be flagged. The exemption is intentionally narrow: it only recognises a
    // parameter named exactly "messageTemplate" declared on another method of the same
    // StartupVerificationContext type, so it cannot be used to launder an arbitrary variable in
    // caller code.
    private static bool IsForwardedMessageTemplateParameter(IOperation value, INamedTypeSymbol containingType)
    {
        if (value is not IParameterReferenceOperation { Parameter: { Name: "messageTemplate" } parameter })
            return false;

        return SymbolEqualityComparer.Default.Equals(parameter.ContainingSymbol?.ContainingType, containingType);
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
