using ZeeKayDa.Auth.Stores;
using ZeeKayDa.Auth.TestKit.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Runs the ADR 0013 §10 conformance kit against <see cref="InMemoryAuthorizationCodeBackingStore"/>.
/// </summary>
public sealed class InMemoryAuthorizationCodeBackingStoreConformanceTests : AuthorizationCodeBackingStoreConformanceTests
{
    protected override IAuthorizationCodeBackingStore CreateStore() => new InMemoryAuthorizationCodeBackingStore();

    // Pure in-process ConcurrentDictionary with no injectable transport dependency — there is
    // genuinely nothing to fail, so the fault-injection tests are deliberately skipped here.
    protected override IAuthorizationCodeBackingStore? CreateFaultInjectedStore(Exception fault) => null;
}
