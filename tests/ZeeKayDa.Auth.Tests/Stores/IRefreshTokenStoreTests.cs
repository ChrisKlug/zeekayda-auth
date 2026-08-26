using System.Reflection;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Verifies the sealing mechanism of <see cref="IRefreshTokenStore"/>: the interface stays
/// implementable from a friend assembly (this test project), but
/// carries exactly one internal member that blocks a genuine third-party implementation.
/// </summary>
public sealed class IRefreshTokenStoreTests
{
    [Fact]
    public void IRefreshTokenStore_declares_exactly_one_internal_method()
    {
        var internalMethods = typeof(IRefreshTokenStore)
            .GetMethods(BindingFlags.NonPublic | BindingFlags.Instance)
            .Where(m => !m.IsPublic)
            .ToList();

        internalMethods.Should().ContainSingle(
            because: "an internal member is what blocks third-party implementation of this " +
                     "framework-sealed interface, and there must be exactly one");
    }

    [Fact]
    public void IRefreshTokenStore_internal_method_is_named_SealAsFrameworkOwnedProtocol()
    {
        var internalMethod = typeof(IRefreshTokenStore)
            .GetMethods(BindingFlags.NonPublic | BindingFlags.Instance)
            .Single(m => !m.IsPublic);

        internalMethod.Name.Should().Be("SealAsFrameworkOwnedProtocol");
    }
}
