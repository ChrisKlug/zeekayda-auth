using System.Reflection;
using ZeeKayDa.Auth.AspNetCore.ClientAuthentication;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.AspNetCore.Tests.Architecture;

/// <summary>
/// Client secrets reach only the code that stores clients and the code that authenticates them;
/// everything else sees <see cref="IClient"/>.
/// </summary>
public sealed class ClientCredentialsReachTests
{
    private static readonly string[] AllowedNamespaces =
    [
        typeof(IClientWithCredentials).Namespace!,
        typeof(CompositeClientAuthenticator).Namespace!,
    ];

    [Fact]
    public void Only_client_storage_and_client_authentication_hold_IClientWithCredentials()
    {
        const BindingFlags Declared = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance
            | BindingFlags.Static | BindingFlags.DeclaredOnly;

        var holders = new[] { typeof(IClient).Assembly, typeof(CompositeClientAuthenticator).Assembly }
            .SelectMany(assembly => assembly.GetTypes())
            .Where(type => !AllowedNamespaces.Contains(type.Namespace))
            .SelectMany(type => type.GetFields(Declared).Select(f => (Owner: type, Member: f.Name, Type: f.FieldType))
                .Concat(type.GetProperties(Declared).Select(p => (Owner: type, Member: p.Name, Type: p.PropertyType)))
                .Concat(type.GetMethods(Declared).SelectMany(m =>
                    m.GetParameters().Select(p => (Owner: type, Member: $"{m.Name}({p.Name})", Type: p.ParameterType))
                        .Append((Owner: type, Member: $"{m.Name}()", Type: m.ReturnType)))))
            .Where(member => Mentions(member.Type))
            .Select(member => $"{member.Owner.FullName}.{member.Member}");

        holders.Should().BeEmpty();
    }

    private static bool Mentions(Type type) =>
        type == typeof(IClientWithCredentials)
        || (type.HasElementType && Mentions(type.GetElementType()!))
        || (type.IsGenericType && type.GetGenericArguments().Any(Mentions));
}
