using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("ZeeKayDa.Auth.Tests")]
[assembly: InternalsVisibleTo("ZeeKayDa.Auth.AspNetCore")]
[assembly: InternalsVisibleTo("ZeeKayDa.Auth.AspNetCore.Tests")]
// ZeeKayDa.Auth.FileSystem reuses PosixInterop.GetLinkOwnerUid (LocalSigningKeyFileSystem.cs) to
// apply the same root-owned-directory trust anchor to its own symlink validation, rather than
// duplicating the per-platform stat()/lstat() P/Invoke a second time. GetLinkOwnerUid (lstat), not
// GetOwnerUid (stat), is load-bearing here — see FileSigningKeyReader.ValidateNoUntrustedSymlinkedAncestorUnix.
// See also ADR 0012 Amendment 3 for why this is IVT rather than a public promotion or a duplicated copy.
[assembly: InternalsVisibleTo("ZeeKayDa.Auth.FileSystem")]
// ZeeKayDa.Auth.Windows reuses ProcessIdentityHelper (ProcessIdentityHelper.cs) for its
// access-denied diagnostic messages, so the best-effort process-identity resolution and
// formatting logic is implemented once rather than duplicated verbatim across the two signing
// providers. See PR #410's review discussion for why this is IVT rather than a public promotion.
[assembly: InternalsVisibleTo("ZeeKayDa.Auth.Windows")]
// ZeeKayDa.Auth.TestKit ships the conformance kit for the IAuthorizationCodeBackingStore
// extension point (ADR 0013 §10). It needs friend access to construct StoreKey internally so
// that a genuine third party can derive the kit from their own test project without ever being
// able to construct a StoreKey themselves (StoreKey's constructor stays internal — see StoreKey.cs).
[assembly: InternalsVisibleTo("ZeeKayDa.Auth.TestKit")]
