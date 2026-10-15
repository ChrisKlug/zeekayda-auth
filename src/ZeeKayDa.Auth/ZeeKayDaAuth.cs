using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("ZeeKayDa.Auth.Tests")]
[assembly: InternalsVisibleTo("ZeeKayDa.Auth.AspNetCore")]
[assembly: InternalsVisibleTo("ZeeKayDa.Auth.AspNetCore.Tests")]
// The TestKit builds StoreKey, SigningKeyRing and SanitizingLogger for third-party tests, so their
// constructors can stay internal.
[assembly: InternalsVisibleTo("ZeeKayDa.Auth.TestKit")]
