using ZeeKayDa.Auth.Stores;
using ZeeKayDa.Auth.TestKit.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Runs the refresh-token-grant-store conformance kit against <see cref="InMemoryRefreshTokenBackingStore"/>.
/// </summary>
public sealed class InMemoryRefreshTokenBackingStoreConformanceTests : RefreshTokenBackingStoreConformanceTests
{
    protected override IRefreshTokenBackingStore CreateStore() => new InMemoryRefreshTokenBackingStore();

    // The mid-revoke case also asserts the own Status of a grant inserted after the revoke has
    // returned, which this store does not set retroactively; its family record makes the
    // IsFamilyRevokedAsync gate refuse that grant instead.
    protected override bool SupportsMidRevokeInsertCompleteness => false;

    // Pure in-process ConcurrentDictionary with no injectable transport dependency — there is
    // genuinely nothing to fail, so the fault-injection tests are deliberately skipped here.
    protected override IRefreshTokenBackingStore? CreateFaultInjectedStore(Exception fault) => null;
}
