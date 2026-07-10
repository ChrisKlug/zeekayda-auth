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
