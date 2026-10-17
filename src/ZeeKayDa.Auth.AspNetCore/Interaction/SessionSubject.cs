using System.Runtime.CompilerServices;

namespace ZeeKayDa.Auth.AspNetCore.Interaction;

/// <summary>
/// A subject the SSO session may be established for: 1–255 printable ASCII characters with no space.
/// Holding one proves the rule was applied, since <see cref="From"/> is the only way to make one.
/// </summary>
internal sealed class SessionSubject
{
    private const int MaxLength = 255;

    private SessionSubject(string value) => Value = value;

    public string Value { get; }

    /// <exception cref="ArgumentNullException"><paramref name="subject"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="subject"/> is not 1–255 printable ASCII characters with no space.
    /// </exception>
    public static SessionSubject From(string subject, [CallerArgumentExpression(nameof(subject))] string? paramName = null)
    {
        ArgumentNullException.ThrowIfNull(subject, paramName);

        if (subject.Length is 0 or > MaxLength || subject.AsSpan().ContainsAnyExceptInRange('\x21', '\x7E'))
        {
            throw new ArgumentException(
                "The subject must be 1–255 printable ASCII characters (0x21–0x7E), with no space: OpenID " +
                "Connect Core §2 caps sub at 255 ASCII characters, and a subject is compared exactly.",
                paramName);
        }

        return new SessionSubject(subject);
    }
}
