namespace Rabits.Domain.Recon;

public enum SecurityFindingSeverity
{
    Info = 0,
    Low,
    Medium,
    High,
}

/// <summary>One security-relevant observation about an HTTP response's headers.</summary>
public sealed record SecurityHeaderFinding(
    string Header,
    bool Present,
    SecurityFindingSeverity Severity,
    string Detail,
    string? Value = null);

/// <summary>
/// Analyzes HTTP response headers for common hardening gaps (missing protective headers) and
/// exposure (verbose fingerprinting headers). Pure domain logic — no I/O.
/// </summary>
public static class SecurityHeaders
{
    private static readonly (string Header, SecurityFindingSeverity Severity, string Missing)[] Protective =
    {
        ("Strict-Transport-Security", SecurityFindingSeverity.High, "No HSTS — connection can be downgraded to HTTP."),
        ("Content-Security-Policy", SecurityFindingSeverity.High, "No CSP — reduced protection against XSS/injection."),
        ("X-Frame-Options", SecurityFindingSeverity.Medium, "No anti-clickjacking header."),
        ("X-Content-Type-Options", SecurityFindingSeverity.Medium, "No nosniff — MIME-type sniffing possible."),
        ("Referrer-Policy", SecurityFindingSeverity.Low, "No referrer policy set."),
        ("Permissions-Policy", SecurityFindingSeverity.Low, "No permissions policy set."),
    };

    private static readonly (string Header, string Detail)[] Exposure =
    {
        ("Server", "Server software disclosed."),
        ("X-Powered-By", "Backend technology disclosed."),
        ("X-AspNet-Version", "ASP.NET version disclosed."),
        ("X-AspNetMvc-Version", "ASP.NET MVC version disclosed."),
    };

    public static IReadOnlyList<SecurityHeaderFinding> Analyze(IReadOnlyDictionary<string, string> headers)
    {
        var findings = new List<SecurityHeaderFinding>();

        foreach (var (header, severity, missing) in Protective)
        {
            var present = TryGet(headers, header, out var value);
            findings.Add(new SecurityHeaderFinding(
                header, present,
                present ? SecurityFindingSeverity.Info : severity,
                present ? "Present." : missing,
                value));
        }

        foreach (var (header, detail) in Exposure)
        {
            if (TryGet(headers, header, out var value))
                findings.Add(new SecurityHeaderFinding(header, true, SecurityFindingSeverity.Low, detail, value));
        }

        return findings;
    }

    private static bool TryGet(IReadOnlyDictionary<string, string> headers, string name, out string? value)
    {
        foreach (var kvp in headers)
        {
            if (string.Equals(kvp.Key, name, StringComparison.OrdinalIgnoreCase))
            {
                value = kvp.Value;
                return true;
            }
        }
        value = null;
        return false;
    }
}
