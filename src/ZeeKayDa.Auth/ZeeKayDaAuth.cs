using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("ZeeKayDa.Auth.Tests")]
[assembly: InternalsVisibleTo("ZeeKayDa.Auth.AspNetCore")]
[assembly: InternalsVisibleTo("ZeeKayDa.Auth.AspNetCore.Tests")]
// ZeeKayDa.Auth.TestKit ships the conformance kit for the IAuthorizationCodeBackingStore
// extension point. It needs friend access to construct StoreKey internally so
// that a genuine third party can derive the kit from their own test project without ever being
// able to construct a StoreKey themselves (StoreKey's constructor stays internal — see StoreKey.cs).
// Its SigningKeyRingHarness constructs the ring and awaits its transitions the same way, so a
// signing key source's own tests can drive the ring while its constructor stays internal, and its
// TestSanitizingLogger constructs a SanitizingLogger for tests while that constructor stays internal.
[assembly: InternalsVisibleTo("ZeeKayDa.Auth.TestKit")]
