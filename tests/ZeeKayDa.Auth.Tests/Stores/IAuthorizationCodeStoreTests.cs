using System.Reflection;
using ZeeKayDa.Auth.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Verifies the sealing mechanism of <see cref="IAuthorizationCodeStore"/>: the interface stays
/// implementable from a friend assembly (this test project), but carries internal members that
/// block a genuine third-party implementation — and keep the interaction claim out of host code.
/// </summary>
public sealed class IAuthorizationCodeStoreTests
{
    [Fact]
    public void IAuthorizationCodeStore_declares_its_sealing_member_internally()
    {
        var internalMethods = typeof(IAuthorizationCodeStore)
            .GetMethods(BindingFlags.NonPublic | BindingFlags.Instance)
            .Where(m => !m.IsPublic)
            .Select(m => m.Name);

        internalMethods.Should().Contain("SealAsFrameworkOwnedProtocol",
            because: "an internal member is what blocks third-party implementation of this framework-sealed interface");
    }

    [Fact]
    public void IAuthorizationCodeStore_keeps_the_interaction_claim_internal()
    {
        // A claim taken from host code would suppress an interaction's outcome for good, so the
        // member is internal: callable and implementable only by friend assemblies.
        var claim = typeof(IAuthorizationCodeStore)
            .GetMethod("TryClaimInteractionAsync", BindingFlags.NonPublic | BindingFlags.Instance);

        claim.Should().NotBeNull();
        claim!.IsAssembly.Should().BeTrue();
        typeof(IAuthorizationCodeStore).GetMethod("TryClaimInteractionAsync", BindingFlags.Public | BindingFlags.Instance)
            .Should().BeNull("the claim must not be part of the public surface");
    }
}
