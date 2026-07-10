using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace ZeeKayDa.Auth.MacOS.Interop;

/// <summary>
/// A <see cref="SafeHandle"/> wrapping any owned CoreFoundation reference (a <c>CFTypeRef</c>, and
/// therefore also every toll-free-bridged Security.framework type: <c>SecKeyRef</c>,
/// <c>SecCertificateRef</c>, <c>SecIdentityRef</c>, <c>CFDictionaryRef</c>, <c>CFDataRef</c>,
/// <c>CFStringRef</c>, <c>CFErrorRef</c>). Releasing the handle calls <c>CFRelease</c> exactly once,
/// deterministically, whether via explicit <see cref="SafeHandle.Dispose()"/> or finalization.
/// </summary>
/// <remarks>
/// Every native reference this package receives from a function following CoreFoundation's "Create
/// Rule" (a name containing "Create" or "Copy") is wrapped in one of these immediately, so that a
/// thrown exception between acquisition and use can never leak the native reference — mirroring
/// <c>SafeHandle</c>'s standard role for OS handles elsewhere in the BCL (e.g. <c>SafeFileHandle</c>).
/// </remarks>
[SupportedOSPlatform("macos")]
internal sealed class SafeCFTypeRefHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    /// <summary>Initialises an invalid handle; used by the marshaler for <c>out</c> parameters.</summary>
    public SafeCFTypeRefHandle()
        : base(ownsHandle: true)
    {
    }

    /// <summary>Wraps an already-owned CoreFoundation reference obtained via a "Create"/"Copy" function.</summary>
    public SafeCFTypeRefHandle(IntPtr owned)
        : base(ownsHandle: true)
    {
        SetHandle(owned);
    }

    /// <inheritdoc/>
    protected override bool ReleaseHandle()
    {
        CoreFoundationInterop.CFRelease(handle);
        return true;
    }
}
