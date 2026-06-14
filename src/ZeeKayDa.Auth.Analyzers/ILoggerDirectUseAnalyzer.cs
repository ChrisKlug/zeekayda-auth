using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace ZeeKayDa.Auth.Analyzers;

/// <summary>
/// Enforces ADR 0007 §7 log hygiene at compile time: ZeeKayDa services must inject
/// <c>ISanitizingLogger&lt;T&gt;</c> rather than <c>ILogger&lt;T&gt;</c> directly.
/// Diagnostic ID: ZEEKAYDA0001, category: LogHygiene, severity: Error.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class ILoggerDirectUseAnalyzer : DiagnosticAnalyzer
{
    /// <summary>Diagnostic ID emitted when <c>ILogger&lt;T&gt;</c> is used directly in a ZeeKayDa service.</summary>
    public const string DiagnosticId = "ZEEKAYDA0001";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "Direct ILogger<T> use in ZeeKayDa service",
        messageFormat: "Inject ISanitizingLogger<T> instead of ILogger<T> in ZeeKayDa services",
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

        context.RegisterSyntaxNodeAction(AnalyzeParameter, SyntaxKind.Parameter);
        context.RegisterSyntaxNodeAction(AnalyzeField, SyntaxKind.FieldDeclaration);
    }

    private static void AnalyzeParameter(SyntaxNodeAnalysisContext context)
    {
        var parameter = (ParameterSyntax)context.Node;
        if (parameter.Type is null) return;
        if (!IsInZeeKayDaNamespace(parameter)) return;
        if (IsInLoggerImplementation(context, parameter)) return;

        var typeInfo = context.SemanticModel.GetTypeInfo(parameter.Type);
        if (IsDirectILoggerT(typeInfo.Type))
            context.ReportDiagnostic(Diagnostic.Create(Rule, parameter.Type.GetLocation()));
    }

    private static void AnalyzeField(SyntaxNodeAnalysisContext context)
    {
        var field = (FieldDeclarationSyntax)context.Node;
        if (!IsInZeeKayDaNamespace(field)) return;
        if (IsInLoggerImplementation(context, field)) return;

        var typeInfo = context.SemanticModel.GetTypeInfo(field.Declaration.Type);
        if (IsDirectILoggerT(typeInfo.Type))
            context.ReportDiagnostic(Diagnostic.Create(Rule, field.Declaration.Type.GetLocation()));
    }

    /// <summary>
    /// Returns true when the node is inside a type declared in a namespace that starts with
    /// "ZeeKayDa". Handles both file-scoped and block-scoped namespace declarations.
    /// </summary>
    private static bool IsInZeeKayDaNamespace(SyntaxNode node)
    {
        // Walk ancestor namespaces (innermost first) and combine their names in order.
        var parts = new System.Collections.Generic.List<string>();
        foreach (var ns in node.Ancestors().OfType<BaseNamespaceDeclarationSyntax>())
            parts.Insert(0, ns.Name.ToString());

        if (parts.Count == 0) return false;
        var fullNamespace = string.Join(".", parts);
        return fullNamespace.StartsWith("ZeeKayDa.", System.StringComparison.Ordinal)
            && !fullNamespace.StartsWith("ZeeKayDa.Auth.Analyzers", System.StringComparison.Ordinal);
    }

    /// <summary>
    /// Returns true when the containing type itself implements <c>ILogger&lt;T&gt;</c> — i.e. it
    /// IS a logger wrapper (like <c>SecretSanitizingLogger&lt;T&gt;</c>) and therefore legitimately
    /// accepts a raw <c>ILogger&lt;T&gt;</c> as its inner target.
    /// </summary>
    private static bool IsInLoggerImplementation(SyntaxNodeAnalysisContext context, SyntaxNode node)
    {
        var typeDecl = node.Ancestors().OfType<BaseTypeDeclarationSyntax>().FirstOrDefault();
        if (typeDecl is null) return false;

        var typeSymbol = context.SemanticModel.GetDeclaredSymbol(typeDecl);
        return typeSymbol?.AllInterfaces.Any(i =>
            i.IsGenericType &&
            i.ContainingNamespace?.ToDisplayString() == "Microsoft.Extensions.Logging" &&
            i.Name == "ILogger" &&
            i.TypeArguments.Length == 1) ?? false;
    }

    private static bool IsDirectILoggerT(ITypeSymbol? type)
    {
        if (type is not INamedTypeSymbol namedType || !namedType.IsGenericType)
            return false;

        var definition = namedType.OriginalDefinition;
        return definition.ContainingNamespace?.ToDisplayString() == "Microsoft.Extensions.Logging"
            && definition.Name == "ILogger"
            && definition.TypeParameters.Length == 1;
    }
}
