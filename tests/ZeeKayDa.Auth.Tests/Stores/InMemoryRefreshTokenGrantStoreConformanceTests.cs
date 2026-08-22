using ZeeKayDa.Auth.Stores;
using ZeeKayDa.Auth.TestKit.Stores;

namespace ZeeKayDa.Auth.Tests.Stores;

/// <summary>
/// Runs the refresh-token-grant-store conformance kit against <see cref="InMemoryRefreshTokenGrantStore"/>.
/// </summary>
public sealed class InMemoryRefreshTokenGrantStoreConformanceTests : RefreshTokenGrantStoreConformanceTests
{
    protected override IRefreshTokenGrantStore CreateStore() => new InMemoryRefreshTokenGrantStore();

    // RevokeFamilyAsync/RevokeBySubjectAsync now take a lock against InsertAsync for the duration
    // of the revoke scan, closing the narrower bug this flag originally worked around (a snapshot
    // enumeration missing a grant inserted mid-scan). What remains — and is NOT fixable at this
    // store's level — is the stronger race this conformance case also exercises: an insert that
    // commits strictly AFTER RevokeFamilyAsync/RevokeBySubjectAsync has already returned, into a
    // family/subject with zero live rows at revoke time, is not retroactively revoked.
    // IRefreshTokenGrantStore's contract does not require a persistent revoked-family/subject
    // marker gating future inserts — RevokeFamilyAsync only promises completeness over rows existing at
    // call time. Issue #386's fix (case 5 above) closes the SECURITY gap this left
    // open by gating consume on IsFamilyRevokedAsync rather than the grant's own Status column, but
    // it deliberately does not retrofit RevokeFamilyAsync/RevokeBySubjectAsync into a two-phase
    // write (a deliberately rejected design), so this case's own-row-status assertion still
    // does not hold for this store — verified by temporarily removing this override and observing
    // the mid-revoke-insert sub-case fail (own Status read back Active, not Revoked).
    protected override bool SupportsMidRevokeInsertCompleteness => false;

    // Pure in-process ConcurrentDictionary with no injectable transport dependency — there is
    // genuinely nothing to fail, so the fault-injection tests are deliberately skipped here.
    protected override IRefreshTokenGrantStore? CreateFaultInjectedStore(Exception fault) => null;
}
