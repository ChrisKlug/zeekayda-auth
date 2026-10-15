using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace ZeeKayDa.Auth.FileSystem;

/// <summary>
/// <c>lstat()</c>, <c>fstat()</c> and <c>geteuid()</c> for Unix ownership checks. No <c>stat()</c>: it
/// follows a symlink to an owner the attacker chooses. One stat struct per kernel ABI, bound up to <c>st_uid</c>.
/// </summary>
[ExcludeFromCodeCoverage(Justification = "Each architecture-specific lstat and fstat branch is reachable only on the one architecture whose ABI it binds, so no single runner can cover them all. FileSigningKeyReaderTests exercises whichever branch the runner's architecture selects.")]
internal static partial class PosixInterop
{
    /// <summary>
    /// The owner UID of the directory entry itself — a symlink's own owner, not its target's — or
    /// <see langword="null"/> if <c>lstat()</c> fails.
    /// </summary>
    [UnsupportedOSPlatform("windows")]
    internal static uint? GetLinkOwnerUid(string path)
    {
        // On x86_64 macOS the plain symbol keeps the legacy 32-bit-inode layout; $INODE64 is the one StatMacOs binds.
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return (RuntimeInformation.OSArchitecture == Architecture.X64
                ? NativeLstatMacOsX64(path, out var macBuf)
                : NativeLstatMacOs(path, out macBuf)) == 0 ? macBuf.st_uid : null;
        }

        if (RuntimeInformation.OSArchitecture == Architecture.X64)
            return NativeLstatLinuxX64(path, out var x64Buf) == 0 ? x64Buf.st_uid : null;

        if (RuntimeInformation.OSArchitecture is Architecture.Arm64 or Architecture.RiscV64)
            return NativeLstatLinuxArm64(path, out var arm64Buf) == 0 ? arm64Buf.st_uid : null;

        return null;
    }

    /// <summary>The owner UID of the open file, whatever the path now names, or <see langword="null"/> if <c>fstat()</c> fails.</summary>
    [UnsupportedOSPlatform("windows")]
    internal static uint? GetOwnerUid(SafeFileHandle handle)
    {
        // On x86_64 macOS the plain symbol keeps the legacy 32-bit-inode layout; $INODE64 is the one StatMacOs binds.
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return (RuntimeInformation.OSArchitecture == Architecture.X64
                ? NativeFstatMacOsX64(handle, out var macBuf)
                : NativeFstatMacOs(handle, out macBuf)) == 0 ? macBuf.st_uid : null;
        }

        if (RuntimeInformation.OSArchitecture == Architecture.X64)
            return NativeFstatLinuxX64(handle, out var x64Buf) == 0 ? x64Buf.st_uid : null;

        if (RuntimeInformation.OSArchitecture is Architecture.Arm64 or Architecture.RiscV64)
            return NativeFstatLinuxArm64(handle, out var arm64Buf) == 0 ? arm64Buf.st_uid : null;

        return null;
    }

    /// <summary>Returns the process's effective UID.</summary>
    [UnsupportedOSPlatform("windows")]
    internal static uint GetEffectiveUid() => NativeGeteuid();

    [LibraryImport("libc", EntryPoint = "geteuid")]
    [UnsupportedOSPlatform("windows")]
    private static partial uint NativeGeteuid();

    [LibraryImport("libc", EntryPoint = "fstat", SetLastError = true)]
    [UnsupportedOSPlatform("windows")]
    private static partial int NativeFstatMacOs(SafeFileHandle handle, out StatMacOs buf);

    [LibraryImport("libc", EntryPoint = "fstat$INODE64", SetLastError = true)]
    [UnsupportedOSPlatform("windows")]
    private static partial int NativeFstatMacOsX64(SafeFileHandle handle, out StatMacOs buf);

    [LibraryImport("libc", EntryPoint = "fstat", SetLastError = true)]
    [UnsupportedOSPlatform("windows")]
    private static partial int NativeFstatLinuxX64(SafeFileHandle handle, out StatLinuxX64 buf);

    [LibraryImport("libc", EntryPoint = "fstat", SetLastError = true)]
    [UnsupportedOSPlatform("windows")]
    private static partial int NativeFstatLinuxArm64(SafeFileHandle handle, out StatLinuxArm64 buf);

    [LibraryImport("libc", EntryPoint = "lstat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [UnsupportedOSPlatform("windows")]
    private static partial int NativeLstatMacOs(string path, out StatMacOs buf);

    [LibraryImport("libc", EntryPoint = "lstat$INODE64", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [UnsupportedOSPlatform("windows")]
    private static partial int NativeLstatMacOsX64(string path, out StatMacOs buf);

    [LibraryImport("libc", EntryPoint = "lstat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [UnsupportedOSPlatform("windows")]
    private static partial int NativeLstatLinuxX64(string path, out StatLinuxX64 buf);

    [LibraryImport("libc", EntryPoint = "lstat", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
    [UnsupportedOSPlatform("windows")]
    private static partial int NativeLstatLinuxArm64(string path, out StatLinuxArm64 buf);

    /// <summary>
    /// macOS / BSD stat struct (64-bit inode layout: arm64, and x86_64 through the <c>$INODE64</c> symbols; 144 bytes total). Fields in native ABI order.
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
