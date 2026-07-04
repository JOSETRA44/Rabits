using Rabits.Domain.Recon;

namespace Rabits.Tests.Domain;

public class SecurityHeadersTests
{
    [Fact]
    public void Flags_missing_protective_headers_and_present_ones()
    {
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["Strict-Transport-Security"] = "max-age=31536000",
            ["Server"] = "nginx",
        };

        var findings = SecurityHeaders.Analyze(headers);

        var hsts = findings.Single(f => f.Header == "Strict-Transport-Security");
        Assert.True(hsts.Present);
        Assert.Equal(SecurityFindingSeverity.Info, hsts.Severity);

        var csp = findings.Single(f => f.Header == "Content-Security-Policy");
        Assert.False(csp.Present);
        Assert.Equal(SecurityFindingSeverity.High, csp.Severity);

        Assert.Contains(findings, f => f.Header == "Server" && f.Present);
    }

    [Fact]
    public void Header_matching_is_case_insensitive()
    {
        var headers = new Dictionary<string, string> { ["x-frame-options"] = "DENY" };
        var finding = SecurityHeaders.Analyze(headers).Single(f => f.Header == "X-Frame-Options");
        Assert.True(finding.Present);
    }
}
