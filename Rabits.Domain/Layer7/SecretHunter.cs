using System.Text.RegularExpressions;
using Rabits.Domain.Recon;

namespace Rabits.Domain.Layer7;

/// <summary>
/// High-performance static secret scanner. Uses .NET 8 source-generated regexes (compiled at build
/// time) for a curated ruleset, plus a Shannon-entropy pass to catch generic high-entropy tokens.
/// Pure and deterministic — no I/O — so it is fully unit-testable and reusable by GUI and CLI.
/// Matches are redacted; the raw secret value is never returned.
/// </summary>
public static partial class SecretHunter
{
    private const int MaxFindingsPerScan = 500;
    private const int MaxEntropyFindings = 30;
    private const int MinEntropyTokenLength = 28;
    private const double EntropyThreshold = 4.5;

    private static readonly SecretRule[] Rules =
    {
        new("AWS Access Key ID", "aws", SecurityFindingSeverity.High, AwsAccessKey()),
        new("AWS Secret Access Key", "aws", SecurityFindingSeverity.High, AwsSecretKey()),
        new("Google API Key", "google", SecurityFindingSeverity.High, GoogleApiKey()),
        new("Google OAuth Client Secret", "google", SecurityFindingSeverity.High, GoogleOAuthSecret()),
        new("GitHub Token", "github", SecurityFindingSeverity.High, GitHubToken()),
        new("Slack Token", "slack", SecurityFindingSeverity.High, SlackToken()),
        new("Slack Webhook", "slack", SecurityFindingSeverity.Medium, SlackWebhook()),
        new("Stripe Secret Key", "stripe", SecurityFindingSeverity.High, StripeSecret()),
        new("Stripe Publishable Key", "stripe", SecurityFindingSeverity.Low, StripePublishable()),
        new("Twilio API Key", "twilio", SecurityFindingSeverity.Medium, TwilioKey()),
        new("Private Key Block", "pki", SecurityFindingSeverity.High, PrivateKey()),
        new("JSON Web Token", "jwt", SecurityFindingSeverity.Medium, Jwt()),
        new("Supabase URL", "supabase", SecurityFindingSeverity.Low, SupabaseUrl()),
        new("Generic Secret Assignment", "generic", SecurityFindingSeverity.Medium, GenericAssignment()),
        new("Bearer Token", "generic", SecurityFindingSeverity.Low, BearerToken()),
    };

    public static IReadOnlyList<SecretFinding> Scan(string content, string source)
    {
        if (string.IsNullOrEmpty(content)) return Array.Empty<SecretFinding>();

        var findings = new List<SecretFinding>();
        var seen = new HashSet<string>();

        foreach (var rule in Rules)
        {
            foreach (Match match in rule.Pattern.Matches(content))
            {
                if (findings.Count >= MaxFindingsPerScan) return findings;
                Add(findings, seen, new SecretFinding
                {
                    RuleName = rule.Name,
                    Category = rule.Category,
                    Severity = rule.Severity,
                    RedactedMatch = Redact(match.Value.Trim()),
                    Source = source,
                });
            }
        }

        ScanEntropy(content, source, findings, seen);
        return findings;
    }

    private static void ScanEntropy(string content, string source, List<SecretFinding> findings, HashSet<string> seen)
    {
        var entropyCount = 0;
        foreach (Match token in EntropyCandidate().Matches(content))
        {
            if (findings.Count >= MaxFindingsPerScan || entropyCount >= MaxEntropyFindings) return;

            var value = token.Value;
            if (value.Length < MinEntropyTokenLength) continue;

            var entropy = ShannonEntropy(value);
            if (entropy < EntropyThreshold) continue;

            var before = findings.Count;
            Add(findings, seen, new SecretFinding
            {
                RuleName = "High-Entropy String",
                Category = "entropy",
                Severity = SecurityFindingSeverity.Low,
                RedactedMatch = Redact(value),
                Source = source,
                Entropy = Math.Round(entropy, 2),
            });
            if (findings.Count > before) entropyCount++;
        }
    }

    private static void Add(List<SecretFinding> findings, HashSet<string> seen, SecretFinding finding)
    {
        if (seen.Add(finding.Key)) findings.Add(finding);
    }

    /// <summary>Shannon entropy in bits per character.</summary>
    public static double ShannonEntropy(string value)
    {
        if (value.Length == 0) return 0;
        var counts = new Dictionary<char, int>();
        foreach (var c in value)
            counts[c] = counts.GetValueOrDefault(c) + 1;

        var entropy = 0.0;
        foreach (var count in counts.Values)
        {
            var p = (double)count / value.Length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    /// <summary>Keeps a short prefix/suffix and masks the middle, so a finding is identifiable but not usable.</summary>
    public static string Redact(string value)
    {
        var oneLine = value.ReplaceLineEndings(" ").Trim();
        if (oneLine.Length <= 8)
            return $"{oneLine[0]}***({oneLine.Length})";

        var keepFront = Math.Min(6, oneLine.Length / 4);
        return $"{oneLine[..keepFront]}…{oneLine[^2..]} ({oneLine.Length} chars)";
    }

    // ── Source-generated regexes (.NET 8) ─────────────────────────────────────────────────────
    [GeneratedRegex(@"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")]
    private static partial Regex AwsAccessKey();

    [GeneratedRegex(@"(?i)aws.{0,20}?(?:secret|access).{0,20}?[""'][0-9a-zA-Z/+]{40}[""']")]
    private static partial Regex AwsSecretKey();

    [GeneratedRegex(@"\bAIza[0-9A-Za-z\-_]{35}\b")]
    private static partial Regex GoogleApiKey();

    [GeneratedRegex(@"\bGOCSPX-[0-9A-Za-z\-_]{20,}\b")]
    private static partial Regex GoogleOAuthSecret();

    [GeneratedRegex(@"\bgh[pousr]_[0-9A-Za-z]{36,}\b")]
    private static partial Regex GitHubToken();

    [GeneratedRegex(@"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b")]
    private static partial Regex SlackToken();

    [GeneratedRegex(@"https://hooks\.slack\.com/services/[A-Za-z0-9/]{40,}")]
    private static partial Regex SlackWebhook();

    [GeneratedRegex(@"\b[sr]k_live_[0-9a-zA-Z]{20,}\b")]
    private static partial Regex StripeSecret();

    [GeneratedRegex(@"\bpk_live_[0-9a-zA-Z]{20,}\b")]
    private static partial Regex StripePublishable();

    [GeneratedRegex(@"\bSK[0-9a-fA-F]{32}\b")]
    private static partial Regex TwilioKey();

    [GeneratedRegex(@"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")]
    private static partial Regex PrivateKey();

    [GeneratedRegex(@"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")]
    private static partial Regex Jwt();

    [GeneratedRegex(@"https://[a-z0-9]{20}\.supabase\.co")]
    private static partial Regex SupabaseUrl();

    [GeneratedRegex(@"(?i)(?:api[_-]?key|apikey|access[_-]?token|client[_-]?secret|secret|password)\s*[:=]\s*[""'][0-9a-zA-Z\-_./+=]{16,}[""']")]
    private static partial Regex GenericAssignment();

    [GeneratedRegex(@"(?i)bearer\s+[a-z0-9\-_.=]{20,}")]
    private static partial Regex BearerToken();

    // Excludes '/' so URL/asset paths are not captured as one token (reduces build-hash noise).
    [GeneratedRegex(@"[A-Za-z0-9+_=-]{28,}")]
    private static partial Regex EntropyCandidate();
}
