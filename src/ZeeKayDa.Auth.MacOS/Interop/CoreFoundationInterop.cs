using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace ZeeKayDa.Auth.MacOS.Interop;

/// <summary>
/// Minimal P/Invoke surface over CoreFoundation.framework: the CFDictionary/CFString/CFData/CFNumber
/// primitives needed to build queries for, and read results back from, the Security.framework calls
/// in <see cref="SecurityInterop"/>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Memory ownership.</strong> This codebase follows CoreFoundation's "Create Rule": any
/// function whose name contains "Create" or "Copy" returns an object the caller owns and must
/// release via <see cref="CFRelease"/> exactly once. Functions like <see cref="CFDictionaryGetValue"/>
/// follow the "Get Rule" instead — the returned reference is borrowed from the container that owns
/// it and must never be released by the caller. Every method in this class is documented with which
/// rule it follows; every call site in this package that receives an owned reference wraps it in
/// <see cref="SafeCFTypeRefHandle"/> or explicitly calls <see cref="CFRelease"/> in a
/// <see langword="finally"/> block.
/// </para>
/// <para>
/// Global constants exported by CoreFoundation.framework (e.g. <c>kCFBooleanTrue</c>,
/// <c>kCFTypeDictionaryKeyCallBacks</c>) are data symbols, not functions: <see cref="NativeLibrary.GetExport"/>
/// returns the address of the variable itself, which must then be dereferenced (for a pointer-sized
/// constant, via <see cref="Marshal.ReadIntPtr(nint)"/>) to obtain the actual CFTypeRef value. The
/// dictionary callback tables (<see cref="CFTypeDictionaryKeyCallBacks"/>/<see cref="CFTypeDictionaryValueCallBacks"/>)
/// are the address of a struct, not a pointer-to-a-value, so they are passed to
/// <see cref="CFDictionaryCreate"/> directly, without dereferencing.
/// </para>
/// </remarks>
[SupportedOSPlatform("macos")]
internal static class CoreFoundationInterop
{
    private const string CoreFoundationLib = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private const uint CFStringEncodingUtf8 = 0x08000100;
    private const int CFNumberSInt32Type = 3;

    private static readonly IntPtr LibraryHandle = NativeLibrary.Load(CoreFoundationLib);

    /// <summary>The address of the shared <c>kCFTypeDictionaryKeyCallBacks</c> table (not a value to dereference).</summary>
    internal static readonly IntPtr CFTypeDictionaryKeyCallBacks = NativeLibrary.GetExport(LibraryHandle, "kCFTypeDictionaryKeyCallBacks");

    /// <summary>The address of the shared <c>kCFTypeDictionaryValueCallBacks</c> table (not a value to dereference).</summary>
    internal static readonly IntPtr CFTypeDictionaryValueCallBacks = NativeLibrary.GetExport(LibraryHandle, "kCFTypeDictionaryValueCallBacks");

    /// <summary>The singleton <c>kCFBooleanTrue</c> CFBooleanRef value.</summary>
    internal static readonly IntPtr KCFBooleanTrue = Marshal.ReadIntPtr(NativeLibrary.GetExport(LibraryHandle, "kCFBooleanTrue"));

    [DllImport(CoreFoundationLib)]
    private static extern IntPtr CFDictionaryCreate(
        IntPtr allocator, IntPtr[] keys, IntPtr[] values, nint numValues, IntPtr keyCallBacks, IntPtr valueCallBacks);

    [DllImport(CoreFoundationLib, CharSet = CharSet.Ansi)]
    private static extern IntPtr CFStringCreateWithCString(IntPtr alloc, string cStr, uint encoding);

    [DllImport(CoreFoundationLib)]
    internal static extern void CFRelease(IntPtr cf);

    [DllImport(CoreFoundationLib)]
    private static extern IntPtr CFNumberCreate(IntPtr allocator, int theType, ref int valuePtr);

    [DllImport(CoreFoundationLib)]
    private static extern IntPtr CFDictionaryGetValue(IntPtr theDict, IntPtr key);

    [DllImport(CoreFoundationLib)]
    private static extern byte CFBooleanGetValue(IntPtr theBoolean);

    [DllImport(CoreFoundationLib)]
    private static extern byte CFNumberGetValue(IntPtr number, int theType, out int valuePtr);

    [DllImport(CoreFoundationLib)]
    private static extern byte CFEqual(IntPtr cf1, IntPtr cf2);

    [DllImport(CoreFoundationLib)]
    private static extern nint CFDataGetLength(IntPtr data);

    [DllImport(CoreFoundationLib)]
    private static extern IntPtr CFDataGetBytePtr(IntPtr data);

    [DllImport(CoreFoundationLib)]
    private static extern IntPtr CFDataCreate(IntPtr allocator, byte[] bytes, nint length);

    [DllImport(CoreFoundationLib)]
    private static extern nint CFStringGetLength(IntPtr theString);

    [DllImport(CoreFoundationLib)]
    private static extern byte CFStringGetCString(IntPtr theString, byte[] buffer, nint bufferSize, uint encoding);

    [DllImport(CoreFoundationLib)]
    private static extern IntPtr CFCopyDescription(IntPtr cf);

    /// <summary>
    /// Builds a CFDictionary from the given keys and values (both borrowed references — the
    /// dictionary retains its own references to each via the "copy" key/value callbacks). Create
    /// Rule: the caller owns the returned dictionary and must <see cref="CFRelease"/> it.
    /// </summary>
    internal static IntPtr CreateDictionary(IntPtr[] keys, IntPtr[] values) =>
        CFDictionaryCreate(IntPtr.Zero, keys, values, keys.Length, CFTypeDictionaryKeyCallBacks, CFTypeDictionaryValueCallBacks);

    /// <summary>
    /// Creates a CFString from a managed string, UTF-8 encoded. Create Rule: the caller owns the
    /// result and must <see cref="CFRelease"/> it.
    /// </summary>
    internal static IntPtr CreateString(string value) => CFStringCreateWithCString(IntPtr.Zero, value, CFStringEncodingUtf8);

    /// <summary>Creates a CFNumber from a 32-bit signed integer. Create Rule: caller owns the result.</summary>
    internal static IntPtr CreateNumber(int value) => CFNumberCreate(IntPtr.Zero, CFNumberSInt32Type, ref value);

    /// <summary>Creates a CFData copy of the given bytes. Create Rule: caller owns the result.</summary>
    internal static IntPtr CreateData(byte[] bytes) => CFDataCreate(IntPtr.Zero, bytes, bytes.Length);

    /// <summary>
    /// Looks up <paramref name="key"/> in <paramref name="dictionary"/>. Get Rule: the returned
    /// reference is borrowed from the dictionary and must not be released by the caller.
    /// Returns <see cref="IntPtr.Zero"/> if the key is absent.
    /// </summary>
    internal static IntPtr GetDictionaryValue(IntPtr dictionary, IntPtr key) => CFDictionaryGetValue(dictionary, key);

    /// <summary>Reads the boolean value of a CFBooleanRef.</summary>
    internal static bool GetBooleanValue(IntPtr cfBoolean) => CFBooleanGetValue(cfBoolean) != 0;

    /// <summary>Reads a CFNumber as a 32-bit signed integer.</summary>
    internal static int GetNumberValue(IntPtr cfNumber)
    {
        CFNumberGetValue(cfNumber, CFNumberSInt32Type, out var value);
        return value;
    }

    /// <summary>Reference (pointer) equality of two CFType instances, per <c>CFEqual</c>.</summary>
    internal static bool AreEqual(IntPtr a, IntPtr b) => a == b || CFEqual(a, b) != 0;

    /// <summary>Copies a CFData's bytes into a managed array. Get Rule for the source pointer.</summary>
    internal static byte[] GetDataBytes(IntPtr data)
    {
        var length = (int)CFDataGetLength(data);
        var source = CFDataGetBytePtr(data);
        var bytes = new byte[length];
        if (length > 0)
            Marshal.Copy(source, bytes, 0, length);
        return bytes;
    }

    /// <summary>Converts a CFStringRef to a managed string (UTF-8 decoded). Get Rule for the source pointer.</summary>
    internal static string GetStringValue(IntPtr cfString)
    {
        if (cfString == IntPtr.Zero)
            return string.Empty;

        var length = (int)CFStringGetLength(cfString);
        var bufferSize = length * 4 + 1; // Worst-case UTF-8 expansion plus the trailing NUL.
        var buffer = new byte[bufferSize];
        if (CFStringGetCString(cfString, buffer, bufferSize, CFStringEncodingUtf8) == 0)
            return string.Empty;

        var nul = Array.IndexOf(buffer, (byte)0);
        return System.Text.Encoding.UTF8.GetString(buffer, 0, nul < 0 ? buffer.Length : nul);
    }

    /// <summary>
    /// Renders any CFType's human-readable description (via <c>CFCopyDescription</c>) as a managed
    /// string — the only reliable way to render a <c>CFErrorRef</c>, which is not itself a CFString.
    /// </summary>
    internal static string Describe(IntPtr cf)
    {
        if (cf == IntPtr.Zero)
            return "(null)";

        var description = CFCopyDescription(cf);
        try
        {
            return GetStringValue(description);
        }
        finally
        {
            CFRelease(description);
        }
    }
}
