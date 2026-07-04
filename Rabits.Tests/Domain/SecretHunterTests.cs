using Rabits.Domain.Layer7;
using Rabits.Domain.Recon;

namespace Rabits.Tests.Domain;

public class SecretHunterTests
{
    [Theory]
    [InlineData("AKIAIOSFODNN7EXAMPLE", "AWS Access Key ID")]
    [InlineData("-----BEGIN RSA PRIVATE KEY-----", "Private Key Block")]
    [InlineData("https://abcdefghijklmnopqrst.supabase.co", "Supabase URL")]
    public void Detects_known_secret_formats(string secret, string expectedRule)
    {
        var findings = SecretHunter.Scan($"const x = \"{secret}\";", "test.js");
        Assert.Contains(findings, f => f.RuleName == expectedRule);
    }

    [Fact]
    public void Detects_google_api_key()
    {
        var findings = SecretHunter.Scan("var k='AIza" + new string('X', 35) + "';", "test.js");
        Assert.Contains(findings, f => f.RuleName == "Google API Key");
    }

    [Fact]
    public void Detects_github_token_and_jwt()
    {
        var content = "token=ghp_" + new string('a', 36) +
                      " jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456xyz";
        var findings = SecretHunter.Scan(content, "test.js");
        Assert.Contains(findings, f => f.RuleName == "GitHub Token");
        Assert.Contains(findings, f => f.RuleName == "JSON Web Token");
    }

    [Fact]
    public void Detects_generic_secret_assignment()
    {
        var findings = SecretHunter.Scan("apiKey: \"abcdef1234567890ABCDEF\"", "app.js");
        Assert.Contains(findings, f => f.RuleName == "Generic Secret Assignment");
    }

    [Fact]
    public void Redacts_the_raw_value()
    {
        const string key = "AKIAIOSFODNN7EXAMPLE";
        var finding = SecretHunter.Scan($"k=\"{key}\"", "test.js").First(f => f.RuleName == "AWS Access Key ID");
        Assert.DoesNotContain(key, finding.RedactedMatch);
        Assert.Contains("…", finding.RedactedMatch);
    }

    [Fact]
    public void Deduplicates_repeated_matches()
    {
        const string key = "AKIAIOSFODNN7EXAMPLE";
        var findings = SecretHunter.Scan($"{key} again {key} and {key}", "test.js");
        Assert.Equal(1, findings.Count(f => f.RuleName == "AWS Access Key ID"));
    }

    [Fact]
    public void Does_not_flag_benign_prose()
    {
        var findings = SecretHunter.Scan("The quick brown fox jumps over the lazy dog. Hello world 123.", "readme.txt");
        Assert.Empty(findings);
    }

    [Fact]
    public void Flags_a_high_entropy_token()
    {
        var findings = SecretHunter.Scan("session=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MFFXRVJUWXVpb3A", "app.js");
        Assert.Contains(findings, f => f.RuleName == "High-Entropy String");
    }

    [Fact]
    public void Shannon_entropy_ranks_random_above_repetitive()
    {
        var low = SecretHunter.ShannonEntropy("aaaaaaaaaaaaaaaa");
        var high = SecretHunter.ShannonEntropy("aB3xZ9qL7wE2rT5y");
        Assert.True(high > low);
        Assert.True(low < 0.1);
    }
}
