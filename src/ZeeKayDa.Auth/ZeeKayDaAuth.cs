using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("ZeeKayDa.Auth.Tests")]
[assembly: InternalsVisibleTo("ZeeKayDa.Auth.AspNetCore")]
[assembly: InternalsVisibleTo("ZeeKayDa.Auth.AspNetCore.Tests")]
// ZeeKayDa.Auth.FileSystem reuses PosixInterop.GetOwnerUid (LocalSigningKeyFileSystem.cs) to apply
// the same root-owned-directory trust anchor to its own symlink validation, rather than duplicating
// the per-platform stat() P/Invoke a second time. See FileSigningKeyReader.ValidateNoSymlink.
[assembly: InternalsVisibleTo("ZeeKayDa.Auth.FileSystem")]
