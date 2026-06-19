using System.Collections.Immutable;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace ZeeKayDa.Auth.Analyzers;

/// <summary>
/// Warns when an <c>IClientRepository</c> implementation in an external assembly never references
/// <c>IClientRegistrationValidator</c>. ADR 0007 §6.1 requires every custom repository to resolve
/// the validator from DI and call it before persisting a new or updated client registration.
/// Diagnostic ID: ZEEKAYDA0003, category: Extensibility, severity: Warning.
/// </summary>
[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class ClientRepositoryValidatorAnalyzer : DiagnosticAnalyzer
{
    /// <summary>Diagnostic ID emitted when an <c>IClientRepository</c> implementation never references <c>IClientRegistrationValidator</c>.</summary>
    public const string DiagnosticId = "ZEEKAYDA0003";

    private static readonly DiagnosticDescriptor Rule = new(
        DiagnosticId,
        title: "IClientRepository implementation does not reference IClientRegistrationValidator",
        messageFormat: "'{0}' implements IClientRepository but never references IClientRegistrationValidator. ADR 0007 §6.1 requires every custom IClientRepository to resolve IClientRegistrationValidator from DI and call it before persisting a new or updated client registration. See docs/how-to/implement-custom-extension-points.md for guidance. If you have an intentional custom validation strategy, suppress this diagnostic with a justification comment.",
        category: "Extensibility",
        defaultSeverity: DiagnosticSeverity.Warning,
        isEnabledByDefault: true);

    /// <inheritdoc/>
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(Rule);

    /// <inheritdoc/>
    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterSyntaxNodeAction(
            AnalyzeTypeDeclaration,
            SyntaxKind.ClassDeclaration,
            SyntaxKind.RecordDeclaration,
            SyntaxKind.StructDeclaration,
            SyntaxKind.RecordStructDeclaration);
    }

    private static void AnalyzeTypeDeclaration(SyntaxNodeAnalysisContext context)
    {
        var typeDecl = (BaseTypeDeclarationSyntax)context.Node;

        var typeSymbol = context.SemanticModel.GetDeclaredSymbol(typeDecl);
        if (typeSymbol is null) return;

        if (!ImplementsIClientRepository(typeSymbol)) return;

        // Assembly-name exemption: simple-name check only (no public key token), consistent with ZEEKAYDA0001/0002.
        if (typeSymbol.ContainingAssembly?.Name == "ZeeKayDa.Auth") return;

        if (ReferencesIClientRegistrationValidator(context, typeDecl)) return;

        context.ReportDiagnostic(
            Diagnostic.Create(Rule, typeDecl.Identifier.GetLocation(), typeSymbol.Name));
    }

    private static bool ImplementsIClientRepository(INamedTypeSymbol typeSymbol)
    {
        return typeSymbol.AllInterfaces.Any(IsIClientRepository);
    }

    private static bool IsIClientRepository(INamedTypeSymbol iface)
    {
        return iface.Name == "IClientRepository"
            && iface.ContainingNamespace?.ToDisplayString() == "ZeeKayDa.Auth.Clients"
            && iface.TypeParameters.Length == 0;
    }

    private static bool ReferencesIClientRegistrationValidator(
        SyntaxNodeAnalysisContext context,
        BaseTypeDeclarationSyntax typeDecl)
    {
        return typeDecl.DescendantNodes()
            .OfType<IdentifierNameSyntax>()
            .Select(id => context.SemanticModel.GetSymbolInfo(id))
            .Any(symbolInfo => IsOrReferencesValidator(symbolInfo.Symbol));
    }

    // Note: wrapper interfaces (e.g. IMyValidator : IClientRegistrationValidator) are not detected —
    // intentional heuristic limitation, consistent with issue #230 scope.
    private static bool IsOrReferencesValidator(ISymbol? symbol)
    {
        return symbol switch
        {
            IParameterSymbol param => IsValidatorType(param.Type),
            IFieldSymbol field => IsValidatorType(field.Type),
            IPropertySymbol prop => IsValidatorType(prop.Type),
            ILocalSymbol local => IsValidatorType(local.Type),
            IMethodSymbol method => IsValidatorType(method.ContainingType),
            INamedTypeSymbol namedType => IsValidatorType(namedType),
            _ => false,
        };
    }

    private static bool IsValidatorType(ITypeSymbol? type)
    {
        return type is INamedTypeSymbol named
            && named.Name == "IClientRegistrationValidator"
            && named.ContainingNamespace?.ToDisplayString() == "ZeeKayDa.Auth.Clients";
    }
}
