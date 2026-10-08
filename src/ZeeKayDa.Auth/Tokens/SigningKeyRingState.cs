namespace ZeeKayDa.Auth.Tokens;

/// <summary>
/// What the health check judges, read from the ring as one: the key set it serves, the timeline that
/// set was chosen from, why signing has stopped, and why the last read failed.
/// </summary>
/// <param name="KeySet">The key set the ring serves now.</param>
/// <param name="Timeline">The listed keys and the rules over them; <see langword="null"/> while signing has stopped.</param>
/// <param name="StopReason">The failure code that stopped signing, or <see langword="null"/>.</param>
/// <param name="ReadFailure">Why the last read failed while the ring serves the list before it, or <see langword="null"/>.</param>
internal sealed record SigningKeyRingState(
    SigningKeySet KeySet, SigningKeyTimeline? Timeline, string? StopReason, string? ReadFailure);
