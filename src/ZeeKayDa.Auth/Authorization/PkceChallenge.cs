namespace ZeeKayDa.Auth.Authorization;

/// <summary>
/// The PKCE binding of an authorization request (RFC 7636 §4.3): the code challenge and the
/// method it was derived with, carried as one value so a code either has a complete binding or
/// none at all.
/// </summary>
/// <remarks>
/// The token endpoint recomputes the challenge from the presented <c>code_verifier</c> with
/// <see cref="Method"/> and compares it to <see cref="Challenge"/> in fixed time.
/// </remarks>
public sealed record PkceChallenge
{
    /// <summary>Creates a binding from the challenge a client sent and the method it named.</summary>
    /// <param name="challenge">The Base64url-encoded challenge, as submitted by the client.</param>
    /// <param name="method">The method the challenge was derived with.</param>
    /// <exception cref="ArgumentException"><paramref name="challenge"/> is empty.</exception>
    /// <exception cref="ArgumentNullException"><paramref name="challenge"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="method"/> is not a defined <see cref="CodeChallengeMethod"/>.</exception>
    public PkceChallenge(string challenge, CodeChallengeMethod method)
    {
        ArgumentException.ThrowIfNullOrEmpty(challenge);

        if (!Enum.IsDefined(method))
            throw new ArgumentOutOfRangeException(nameof(method), method, "The code challenge method is not one this server defines.");

        Challenge = challenge;
        Method = method;
    }

    /// <summary>The code challenge, stored exactly as the client submitted it.</summary>
    public string Challenge { get; }

    /// <summary>The method the challenge was derived with.</summary>
    public CodeChallengeMethod Method { get; }
}
