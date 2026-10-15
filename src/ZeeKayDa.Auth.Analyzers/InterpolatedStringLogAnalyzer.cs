using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace ZeeKayDa.Auth.Analyzers;

/// <summary>
/// Requires the message template passed to <c>Log*</c>/<c>BeginScope</c> and to
/// <c>StartupVerificationContext.AddWarning</c> inside ZeeKayDa.Auth's own assemblies to be a
/// compile-time constant. A non-constant string is already fully expanded, so
/// <c>SanitizingLogger</c> can no longer redact its values.
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
        // A security control, not a style rule: marking a file as generated must not switch it off.
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.Analyze | GeneratedCodeAnalysisFlags.ReportDiagnostics);
        context.EnableConcurrentExecution();

        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);

        // A call through a delegate has no logger receiver to check, so the conversion is flagged instead.
        context.RegisterSyntaxNodeAction(
            AnalyzeMethodGroupConversion, SyntaxKind.EqualsValueClause, SyntaxKind.SimpleAssignmentExpression);
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        var invocation = (InvocationExpressionSyntax)context.Node;

        string? methodName = invocation.Expression switch
        {
            MemberAccessExpressionSyntax memberAccess => memberAccess.Name.Identifier.Text,
            MemberBindingExpressionSyntax memberBinding => memberBinding.Name.Identifier.Text,
            IdentifierNameSyntax identifierName => identifierName.Identifier.Text,
            _ => null,
        };
        if (methodName is null) return;

        if (!ZeeKayDaAssemblyGate.IsZeeKayDaAssembly(context.SemanticModel.Compilation)) return;

        if (IsLogMethodName(methodName))
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

        var template = invocation.ArgumentList.Arguments.FirstOrDefault(argument =>
            context.SemanticModel.GetTypeInfo(argument.Expression).Type?.SpecialType == SpecialType.System_String);
        if (template is not null && !context.SemanticModel.GetConstantValue(template.Expression).HasValue)
            context.ReportDiagnostic(Diagnostic.Create(Rule, template.GetLocation()));
    }

    private static bool IsLogMethodName(string methodName) =>
        methodName.StartsWith("Log", System.StringComparison.Ordinal) || methodName == "BeginScope";

    // Static form `LoggerExtensions.LogInformation(logger, ...)` has no Instance; its receiver is the `this` parameter.
    private static ITypeSymbol? ResolveLoggerReceiverType(IInvocationOperation operation)
    {
        if (operation.Instance is not null) return operation.Instance.Type;

        if (!operation.TargetMethod.IsExtensionMethod) return null;

        var thisArgument = operation.Arguments.FirstOrDefault(a => a.Parameter?.Ordinal == 0);
        return thisArgument?.Value.Type;
    }

    // AddWarning's first string parameter is the code, not the template, so the template is found by parameter name.
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
            && containingType.ContainingNamespace?.ToDisplayString() == "ZeeKayDa.Auth.StartupVerification";
    }

    // Flags `Action<string, object?[]> log = logger.LogInformation;`. Only a member access can carry a checkable receiver.
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
        var isLogLike = IsLogMethodName(methodName);
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

        // A delegate with no string parameter cannot carry a template.
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

        // A same-named type in another assembly or namespace must not exempt itself.
        return typeSymbol.ContainingAssembly?.Name == "ZeeKayDa.Auth"
            && typeSymbol is INamedTypeSymbol { Name: "SanitizingLogger", TypeParameters.Length: 1 }
            && typeSymbol.ContainingNamespace?.ToDisplayString() == "ZeeKayDa.Auth.Logging";
    }
}
