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
/// conditional-access, or static extension-method form) inside ZeeKayDa.Auth's own assemblies, and
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
        // This is a security control enforcing the log-never list, not a style
        // preference, so the usual "don't nag about generated code" convention does not apply:
        // classifying a file as generated (by filename, header, [GeneratedCode], or
        // generated_code = true) would otherwise silently suppress the rule with no rule ID
        // in the diff.
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
        context.EnableConcurrentExecution();

        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);

        // Once a Log*/AddWarning method group is converted to a delegate (e.g.
        // `Action<string, object?[]> log = logger.LogInformation;`), the later call through that
        // delegate variable has no ILogger/AddWarning-shaped receiver in its syntax at all — the
        // AnalyzeInvocation checks above have nothing to hook into at the call site. The
        // conversion itself, however, is still syntactically local (a plain member-access
        // expression on the right of an assignment or initializer), so it is flagged there
        // instead. This deliberately does not follow the delegate variable any further —
        // reassignment, parameter passing, and field storage across methods are all out of scope
        // (issue #463).
        context.RegisterSyntaxNodeAction(
            AnalyzeMethodGroupConversion, SyntaxKind.EqualsValueClause, SyntaxKind.SimpleAssignmentExpression);
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        var invocation = (InvocationExpressionSyntax)context.Node;

        // Plain `logger.LogX(...)` uses MemberAccessExpressionSyntax; conditional-access
        // `logger?.LogX(...)` uses MemberBindingExpressionSyntax; an unqualified call with an
        // implicit `this` receiver (e.g. AddWarning(...) called from inside
        // StartupVerificationContext itself) uses IdentifierNameSyntax. Only the method name is
        // needed here to route the call — the receiver itself is resolved from the bound
        // IInvocationOperation, not from this syntax.
        string? methodName = invocation.Expression switch
        {
            MemberAccessExpressionSyntax memberAccess => memberAccess.Name.Identifier.Text,
            MemberBindingExpressionSyntax memberBinding => memberBinding.Name.Identifier.Text,
            IdentifierNameSyntax identifierName => identifierName.Identifier.Text,
            _ => null,
        };
        if (methodName is null) return;

        if (!ZeeKayDaAssemblyGate.IsZeeKayDaAssembly(context.SemanticModel.Compilation)) return;

        if (methodName.StartsWith("Log", System.StringComparison.Ordinal) || methodName == "BeginScope")
        {
            AnalyzeLogInvocation(context, invocation);
            return;
        }

        if (methodName == "AddWarning")
            AnalyzeAddWarningInvocation(context, invocation);
    }

    private static void AnalyzeLogInvocation(SyntaxNodeAnalysisContext context, InvocationExpressionSyntax invocation)
    {
        if (IsInLoggerImplementation(context, invocation)) return;

        if (context.SemanticModel.GetOperation(invocation) is not IInvocationOperation operation) return;

        var receiverType = ResolveLoggerReceiverType(operation);
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

    // The bound operation already distinguishes an ordinary instance call — including a reduced
    // extension-method call such as `logger.LogInformation(...)`, where Instance is the logger —
    // from the fully static call form `LoggerExtensions.LogInformation(logger, ...)`, where
    // Instance is null and the logger is an ordinary argument bound to the extension method's
    // "this" parameter (ordinal 0). Resolving the receiver this way, rather than from syntax,
    // correctly handles named/reordered arguments and never mistakes an unrelated extension
    // method's ILogger-typed argument for its receiver.
    private static ITypeSymbol? ResolveLoggerReceiverType(IInvocationOperation operation)
    {
        if (operation.Instance is not null) return operation.Instance.Type;

        if (!operation.TargetMethod.IsExtensionMethod) return null;

        var thisArgument = operation.Arguments.FirstOrDefault(a => a.Parameter?.Ordinal == 0);
        return thisArgument?.Value.Type;
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
        if (!IsStartupVerificationContextMethod(method)) return;

        var templateArgument = operation.Arguments.FirstOrDefault(a => a.Parameter?.Name == "messageTemplate");
        if (templateArgument is null) return;

        if (templateArgument.Value.ConstantValue.HasValue) return;

        context.ReportDiagnostic(Diagnostic.Create(Rule, templateArgument.Value.Syntax.GetLocation()));
    }

    private static bool IsStartupVerificationContextMethod(IMethodSymbol method)
    {
        return method.ContainingType is { Name: "StartupVerificationContext" } containingType
            && containingType.ContainingNamespace?.ToDisplayString() == "ZeeKayDa.Auth";
    }

    // Flags `Action<string, object?[]> log = logger.LogInformation;` and
    // `someField = warningsCollector.AddWarning;` — a Log*/AddWarning method group converted to a
    // delegate, at the point of conversion. Bare member-access expressions only: a conditional
    // access (`logger?.LogInformation`) cannot form a method group in C#, and an unqualified
    // reference has no receiver to check, so neither shape applies here.
    private static void AnalyzeMethodGroupConversion(SyntaxNodeAnalysisContext context)
    {
        ExpressionSyntax? rhs = context.Node switch
        {
            EqualsValueClauseSyntax equalsValue => equalsValue.Value,
            AssignmentExpressionSyntax assignment => assignment.Right,
            _ => null,
        };
        if (rhs is not MemberAccessExpressionSyntax memberAccess) return;

        var methodName = memberAccess.Name.Identifier.Text;
        var isLogLike = methodName.StartsWith("Log", System.StringComparison.Ordinal) || methodName == "BeginScope";
        if (!isLogLike && methodName != "AddWarning") return;

        if (!ZeeKayDaAssemblyGate.IsZeeKayDaAssembly(context.SemanticModel.Compilation)) return;

        if (context.SemanticModel.GetSymbolInfo(memberAccess).Symbol is not IMethodSymbol method) return;

        if (isLogLike)
        {
            var receiverType = context.SemanticModel.GetTypeInfo(memberAccess.Expression).Type;
            if (receiverType is null || !ImplementsILogger(receiverType)) return;
        }
        else if (!IsStartupVerificationContextMethod(method))
        {
            return;
        }

        // The method group must actually be converting to a delegate shape that could carry a
        // format string — this rules out e.g. capturing BeginScope's generic overloads into an
        // unrelated delegate type that has no string parameter at all.
        var convertedType = context.SemanticModel.GetTypeInfo(rhs).ConvertedType;
        if (convertedType is not INamedTypeSymbol { TypeKind: TypeKind.Delegate } delegateType) return;
        if (delegateType.DelegateInvokeMethod is not { } invokeMethod) return;
        if (!invokeMethod.Parameters.Any(p => p.Type.SpecialType == SpecialType.System_String)) return;

        context.ReportDiagnostic(Diagnostic.Create(Rule, memberAccess.GetLocation()));
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
