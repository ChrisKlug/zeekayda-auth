using System.Runtime.Versioning;

namespace ZeeKayDa.Auth.MacOS.Interop;

/// <summary>
/// Builds a CoreFoundation query/attribute dictionary (as used by <c>SecItemCopyMatching</c> and
/// <c>SecKeyCreateRandomKey</c>) from a small set of key/value pairs, without leaking the
/// intermediate CFString/CFNumber values created along the way.
/// </summary>
/// <remarks>
/// <c>CFDictionaryCreate</c> retains its own reference to every key and value it is given (per the
/// "copy" key/value callbacks passed in <see cref="CoreFoundationInterop.CreateDictionary"/>), so any
/// CFString or CFNumber created solely to populate this dictionary can — and must, to avoid a
/// leak — be released immediately after the dictionary itself is built. <see cref="Build"/> does
/// this automatically for every value added via <see cref="AddOwnedString"/>.
/// </remarks>
[SupportedOSPlatform("macos")]
internal sealed class CFDictionaryBuilder
{
    private readonly List<IntPtr> _keys = [];
    private readonly List<IntPtr> _values = [];
    private readonly List<IntPtr> _ownedTemporaries = [];

    /// <summary>Adds a key/value pair where both are borrowed, long-lived constants (e.g. <c>kSecClass</c> values).</summary>
    public CFDictionaryBuilder Add(IntPtr key, IntPtr value)
    {
        _keys.Add(key);
        _values.Add(value);
        return this;
    }

    /// <summary>Adds a key paired with a freshly created CFString value, which is released once the dictionary is built.</summary>
    public CFDictionaryBuilder AddOwnedString(IntPtr key, string value)
    {
        var cfString = CoreFoundationInterop.CreateString(value);
        _ownedTemporaries.Add(cfString);
        return Add(key, cfString);
    }

    /// <summary>
    /// Builds the dictionary and releases every temporary value created via
    /// <see cref="AddOwnedString"/>. The returned handle owns the dictionary itself.
    /// </summary>
    public SafeCFTypeRefHandle Build()
    {
        var dictionary = CoreFoundationInterop.CreateDictionary([.. _keys], [.. _values]);
        foreach (var temporary in _ownedTemporaries)
            CoreFoundationInterop.CFRelease(temporary);

        return new SafeCFTypeRefHandle(dictionary);
    }
}
