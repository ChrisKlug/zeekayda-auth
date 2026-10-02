using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using ZeeKayDa.Auth;
using ZeeKayDa.Auth.Clients;

namespace ZeeKayDa.Auth.Samples.IdentityServer.ClientSecrets;

/// <summary>
/// bcrypt through BCrypt.Net-Next, a library that writes its own self-describing string
/// (<c>$2b$12$&lt;salt and hash&gt;</c>). The string is stored exactly as the library wrote it, and the
/// library reads it back; this class only checks its shape and cost.
/// </summary>
public sealed partial class BCryptClientSecretHasher : IClientSecretHasher
{
    private const int WorkFactor = 12;

    // OWASP's bcrypt floor, and a ceiling past which one verification costs seconds.
    private const int MinWorkFactor = 10;
    private const int MaxWorkFactor = 14;

    // bcrypt reads only the first 72 bytes; longer secrets would match each other.
    private const int MaxSecretBytes = 72;

    // bcrypt's revisions differ only in old implementation bugs; the library reads all three.
    public IReadOnlySet<string> AlgorithmIds { get; } =
        new HashSet<string>(["2a", "2b", "2y"], StringComparer.Ordinal);

    // The library takes strings only, so the presented secret is copied into one.
    public bool Verify(ReadOnlySpan<char> presented, ClientSecret stored) =>
        Encoding.UTF8.GetByteCount(presented) <= MaxSecretBytes
        && WorkFactorOf(stored) is >= MinWorkFactor and <= MaxWorkFactor
        && BCrypt.Net.BCrypt.Verify(presented.ToString(), stored.Value);

    public ClientSecret Create(ReadOnlySpan<char> plaintext) =>
        Encoding.UTF8.GetByteCount(plaintext) <= MaxSecretBytes
            ? new(BCrypt.Net.BCrypt.HashPassword(plaintext.ToString(), WorkFactor))
            : throw new ArgumentException($"bcrypt reads only the first {MaxSecretBytes} bytes of a secret.", nameof(plaintext));

    public IEnumerable<ZeeKayDaConfigurationFailure> ValidateStoredSecret(ClientSecret stored)
    {
        if (WorkFactorOf(stored) is not { } workFactor)
        {
            yield return new("sample.bcrypt.malformed",
                "A bcrypt secret is not $2a$, $2b$ or $2y$ followed by a two-digit cost and 53 characters of salt and hash.");
        }
        else if (workFactor is < MinWorkFactor or > MaxWorkFactor)
        {
            yield return new("sample.bcrypt.cost_out_of_range",
                $"A bcrypt secret has cost {workFactor}, outside {MinWorkFactor}–{MaxWorkFactor}.");
        }
    }

    private static int? WorkFactorOf(ClientSecret stored) =>
        BCryptString().Match(stored.Value ?? "") is { Success: true } match
            ? int.Parse(match.Groups["cost"].ValueSpan, CultureInfo.InvariantCulture)
            : null;

    [GeneratedRegex(@"\A\$2[aby]\$(?<cost>[0-9]{2})\$[./A-Za-z0-9]{53}\z", RegexOptions.CultureInvariant)]
    private static partial Regex BCryptString();
}
