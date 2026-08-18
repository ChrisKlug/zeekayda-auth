using Microsoft.Extensions.Logging;

namespace ZeeKayDa.Auth.LogHygieneCanary;

/// <summary>
/// Deliberately violates both log-hygiene rules: a direct <see cref="ILogger{TCategoryName}"/>
/// injection (ZEEKAYDA0001) and a non-constant message template (ZEEKAYDA0002). This type must
/// never compile — see the containing project's file for why it exists and how it is invoked.
/// </summary>
public sealed class BadService
{
    public BadService(ILogger<BadService> logger)
    {
        var secret = "leaked-value";
        logger.LogInformation($"Secret was: {secret}");
    }
}
