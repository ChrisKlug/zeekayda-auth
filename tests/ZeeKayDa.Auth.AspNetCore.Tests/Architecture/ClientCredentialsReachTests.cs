using System.Reflection;
using System.Reflection.Emit;
using ZeeKayDa.Auth.AspNetCore.ClientAuthentication;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Architecture;

/// <summary>
/// Client secrets reach only the code that stores clients and the code that authenticates them;
/// everything else sees <see cref="IClient"/>.
/// </summary>
public sealed class ClientCredentialsReachTests
{
    private const BindingFlags Declared = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance
        | BindingFlags.Static | BindingFlags.DeclaredOnly;

    private static readonly string[] AllowedNamespaces =
    [
        typeof(IClientWithCredentials).Namespace!,
        typeof(CompositeClientAuthenticator).Namespace!,
    ];


    [Fact]
    public void Only_client_storage_and_client_authentication_hold_IClientWithCredentials()
    {
        var holders = TypesOutsideTheAllowedNamespaces().SelectMany(type =>
            type.GetFields(Declared).Where(f => Mentions(f.FieldType)).Select(f => $"{type.FullName}.{f.Name}")
                .Concat(type.GetProperties(Declared).Where(p => Mentions(p.PropertyType)).Select(p => $"{type.FullName}.{p.Name}"))
                .Concat(MethodsOf(type).Where(HoldsCredentials).Select(m => $"{type.FullName}.{m.Name}")));

        holders.Should().BeEmpty();
    }

    [Fact]
    public void Only_client_storage_and_client_authentication_look_up_credentials()
    {
        var callers = TypesOutsideTheAllowedNamespaces()
            .SelectMany(type => MethodsOf(type).Where(Calls).Select(m => $"{type.FullName}.{m.Name}"));

        callers.Should().BeEmpty();
    }

    private static IEnumerable<Type> TypesOutsideTheAllowedNamespaces() =>
        new[] { typeof(IClient).Assembly, typeof(CompositeClientAuthenticator).Assembly }
            .SelectMany(assembly => assembly.GetTypes())
            .Where(type => !AllowedNamespaces.Contains(type.Namespace));

    private static IEnumerable<MethodBase> MethodsOf(Type type) =>
        type.GetMethods(Declared).Cast<MethodBase>().Concat(type.GetConstructors(Declared));

    private static bool HoldsCredentials(MethodBase method) =>
        method.GetParameters().Any(p => Mentions(p.ParameterType))
        || (method is MethodInfo info && Mentions(info.ReturnType))
        || (method.GetMethodBody()?.LocalVariables.Any(local => Mentions(local.LocalType)) ?? false);

    // Reads every call and callvirt operand; a byte that only looks like one resolves to nothing.
    private static bool Calls(MethodBase method)
    {
        var il = method.GetMethodBody()?.GetILAsByteArray() ?? [];
        return Enumerable.Range(0, Math.Max(0, il.Length - 4))
            .Where(i => il[i] == OpCodes.Call.Value || il[i] == OpCodes.Callvirt.Value)
            .Any(i => LooksUpCredentials(ResolveOrNull(method.Module, BitConverter.ToInt32(il, i + 1))));
    }

    private static bool LooksUpCredentials(MethodBase? called) =>
        called is not null && (IsResolverCredentialsLookup(called) || IsRepositoryLookup(called));

    private static bool IsResolverCredentialsLookup(MethodBase called) =>
        called.DeclaringType == typeof(ValidatedClientResolver)
        && called.Name == nameof(ValidatedClientResolver.FindClientWithCredentialsAsync);

    // On the interface or on any concrete store.
    private static bool IsRepositoryLookup(MethodBase called) =>
        typeof(IClientRepository).IsAssignableFrom(called.DeclaringType)
        && called.Name == nameof(IClientRepository.FindByClientIdAsync);

    private static MethodBase? ResolveOrNull(Module module, int token)
    {
        try
        {
            return module.ResolveMethod(token);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    // Any type carrying credentials: the interface, the Client record, or another implementation.
    private static bool Mentions(Type type) =>
        typeof(IClientWithCredentials).IsAssignableFrom(type)
        || (type.HasElementType && Mentions(type.GetElementType()!))
        || (type.IsGenericType && type.GetGenericArguments().Any(Mentions));
}
