using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using ZeeKayDa.Auth.MacOS.Interop;

namespace ZeeKayDa.Auth.MacOS.Tests.Integration;

/// <summary>
/// A tiny, test-only P/Invoke surface for fabricating real Keychain items to test against
/// (<c>SecKeyCreateRandomKey</c>). Deliberately kept out of the production
/// <see cref="ZeeKayDa.Auth.MacOS.Interop.SecurityInterop"/> class: the production
/// <see cref="KeychainItemReader"/> is read-only and never generates or writes Keychain items — key
/// generation/rotation is the operator's responsibility (issue #290's explicit scope boundary), so
/// this capability has no business existing in the shipped package.
/// </summary>
[SupportedOSPlatform("macos")]
internal static class TestKeychainInterop
{
    private const string SecurityLib = "/System/Library/Frameworks/Security.framework/Security";

    private static readonly IntPtr LibraryHandle = NativeLibrary.Load(SecurityLib);

    public static readonly IntPtr KSecAttrIsPermanent = Marshal.ReadIntPtr(NativeLibrary.GetExport(LibraryHandle, "kSecAttrIsPermanent"));
    public static readonly IntPtr KSecPublicKeyAttrs = Marshal.ReadIntPtr(NativeLibrary.GetExport(LibraryHandle, "kSecPublicKeyAttrs"));

    [DllImport(SecurityLib)]
    private static extern IntPtr SecKeyCreateRandomKey(IntPtr parameters, out IntPtr error);

    [DllImport(SecurityLib)]
    private static extern int SecItemDelete(IntPtr query);

    /// <summary>
    /// Generates a new key pair and — because <c>kSecAttrIsPermanent</c> is set in
    /// <paramref name="parameters"/> — persists it to the default (login) Keychain, exactly as
    /// <c>SecKeyCreateRandomKey</c>'s own documentation describes for macOS.
    /// </summary>
    public static SafeCFTypeRefHandle CreateRandomKey(IntPtr parameters)
    {
        var keyPtr = SecKeyCreateRandomKey(parameters, out var errorPtr);
        using var error = new SafeCFTypeRefHandle(errorPtr);
        if (keyPtr == IntPtr.Zero)
            throw new InvalidOperationException("SecKeyCreateRandomKey failed: " + CoreFoundationInterop.Describe(error.DangerousGetHandle()));

        return new SafeCFTypeRefHandle(keyPtr);
    }

    /// <summary>
    /// Deletes every key with the given label from the default Keychain, via <c>SecItemDelete</c> —
    /// the <c>security</c> CLI has no direct "delete key by label" subcommand.
    /// </summary>
    /// <remarks>
    /// <c>kSecMatchLimit = kSecMatchLimitAll</c> is required here despite <c>SecItemDelete</c>'s own
    /// header documentation claiming "by default, this function deletes all items matching the
    /// specified query": verified empirically on this SDK/OS that a query with no explicit match
    /// limit returns <c>errSecSuccess</c> (0) but does not actually remove a key pair generated via
    /// <c>SecKeyCreateRandomKey</c> — a subsequent <c>SecItemCopyMatching</c> for the same label,
    /// even from the very same process, still finds it. Adding the explicit limit makes the deletion
    /// actually take effect. Test-only concern: production <see cref="KeychainItemReader"/> never
    /// deletes anything.
    /// </remarks>
    public static void DeleteKeyByLabel(string label)
    {
        using var query = new CFDictionaryBuilder()
            .Add(SecurityInterop.KSecClass, SecurityInterop.KSecClassKey)
            .AddOwnedString(SecurityInterop.KSecAttrLabel, label)
            .Add(SecurityInterop.KSecMatchLimit, SecurityInterop.KSecMatchLimitAll)
            .Build();

        SecItemDelete(query.DangerousGetHandle());
    }
}
