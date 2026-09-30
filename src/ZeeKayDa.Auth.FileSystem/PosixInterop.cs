using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// Provides interop access to <c>lstat()</c> for directory ownership validation on Unix platforms.
/// </summary>
/// <remarks>
/// <para>
/// There is deliberately no <c>stat()</c>-based counterpart. <c>stat()</c> follows a symlink and
/// reports the owner of whatever it points at, which an attacker chooses by choosing where their
/// link points — so every ownership decision in this assembly reads the link entry's own owner.
/// </para>
/// Separate native stat-buffer structs are declared for macOS/BSD and Linux 64-bit because the kernel ABI
/// differs between platforms; only the fields up to <c>st_uid</c> are bound, with the rest covered
/// by blittable padding.
/// </remarks>
[ExcludeFromCodeCoverage(Justification = "Each architecture-specific lstat branch is reachable only on the one architecture whose ABI it binds, so no single runner can cover them all. FileSigningKeyReaderTests exercises whichever branch the runner's architecture selects.")]
internal static partial class PosixInterop
{
    /// <summary>
    /// Returns the UID of the owner of the directory entry at <paramref name="path"/> itself — if
    /// that entry is a symlink, the symlink object's own owner, <strong>not</strong> the owner of
    /// whatever it points at — or <see langword="null"/> if <c>lstat()</c> fails.
    /// </summary>
    /// <remarks>
    /// Deliberately <c>lstat()</c> and never <c>stat()</c>, which follows a symlink to report the
    /// *target's* owner. An unprivileged attacker can create a symlink that points at a root-owned
    /// directory, and <c>stat()</c> on that link would wrongly report root ownership rather than the
    /// attacker's own ownership of the link they created. <c>lstat()</c> reports the link entry's own
    /// owner regardless of what it points at.
    /// </remarks>
    [UnsupportedOSPlatform("windows")]
    internal static uint? GetLinkOwnerUid(string path)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return NativeLstatMacOs(path, out var macBuf) == 0 ? macBuf.st_uid : null;

        if (RuntimeInformation.OSArchitecture == Architecture.X64)
            return NativeLstatLinuxX64(path, out var x64Buf) == 0 ? x64Buf.st_uid : null;

        if (RuntimeInformation.OSArchitecture is Architecture.Arm64 or Architecture.RiscV64)
            return NativeLstatLinuxArm64(path, out var arm64Buf) == 0 ? arm64Buf.st_uid : null;

        return null;
    }

    [LibraryImport("libc", EntryPoint = "lstat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [UnsupportedOSPlatform("windows")]
    private static partial int NativeLstatMacOs(string path, out StatMacOs buf);

    [LibraryImport("libc", EntryPoint = "lstat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [UnsupportedOSPlatform("windows")]
    private static partial int NativeLstatLinuxX64(string path, out StatLinuxX64 buf);

    [LibraryImport("libc", EntryPoint = "lstat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [UnsupportedOSPlatform("windows")]
    private static partial int NativeLstatLinuxArm64(string path, out StatLinuxArm64 buf);

    /// <summary>
    /// macOS / BSD stat struct (arm64, 144 bytes total). Fields in native ABI order.
    /// Layout: dev(4) mode(2) nlink(2) ino(8) uid(4) gid(4) + 120 bytes padding.
    /// Padding uses blittable scalar fields so the struct is compatible with [LibraryImport].
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct StatMacOs
    {
        internal int st_dev;       // offset  0, 4 bytes
        internal ushort st_mode;   // offset  4, 2 bytes
        internal ushort st_nlink;  // offset  6, 2 bytes
        internal ulong st_ino;     // offset  8, 8 bytes
        internal uint st_uid;      // offset 16, 4 bytes ← we need this
        internal uint st_gid;      // offset 20, 4 bytes
        // 120 bytes padding → total 144 bytes (15 × 8)
        private ulong _p0, _p1, _p2, _p3, _p4, _p5, _p6, _p7, _p8, _p9, _p10, _p11, _p12, _p13, _p14;
    }

    /// <summary>
    /// Linux x64 stat struct (144 bytes total). Fields in native ABI order.
    /// Layout: dev(8) ino(8) nlink(8) mode(4) uid(4) gid(4) + 108 bytes padding.
    /// Padding uses blittable scalar fields so the struct is compatible with [LibraryImport].
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct StatLinuxX64
    {
        internal ulong st_dev;     // offset  0, 8 bytes
        internal ulong st_ino;     // offset  8, 8 bytes
        internal ulong st_nlink;   // offset 16, 8 bytes
        internal uint st_mode;     // offset 24, 4 bytes
        internal uint st_uid;      // offset 28, 4 bytes ← we need this
        internal uint st_gid;      // offset 32, 4 bytes
        // 108 bytes padding → total 144 bytes (4 + 13 × 8)
        private uint _p0;          // offset 36, 4 bytes (aligns next field to 8-byte boundary)
        private ulong _p1, _p2, _p3, _p4, _p5, _p6, _p7, _p8, _p9, _p10, _p11, _p12, _p13; // offset 40, 104 bytes
    }

    /// <summary>
    /// Linux arm64 stat struct (128 bytes total). Fields in native ABI order.
    /// Layout: dev(8) ino(8) mode(4) nlink(4) uid(4) gid(4) + 96 bytes padding.
    /// Padding uses blittable scalar fields so the struct is compatible with [LibraryImport].
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct StatLinuxArm64
    {
        internal ulong st_dev;     // offset  0, 8 bytes
        internal ulong st_ino;     // offset  8, 8 bytes
        internal uint st_mode;     // offset 16, 4 bytes
        internal uint st_nlink;    // offset 20, 4 bytes
        internal uint st_uid;      // offset 24, 4 bytes ← we need this
        internal uint st_gid;      // offset 28, 4 bytes
        // 96 bytes padding → total 128 bytes (12 × 8)
        private ulong _p0, _p1, _p2, _p3, _p4, _p5, _p6, _p7, _p8, _p9, _p10, _p11;
    }
}
