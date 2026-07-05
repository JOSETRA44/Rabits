using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Rabits.Application.Abstractions;
using Rabits.Application.Auth;
using Rabits.Application.Hosts;
using Rabits.Application.Layer7;
using Rabits.Application.Recon;
using Rabits.Application.Security;
using Rabits.Application.Wireless;
using Rabits.Domain.Auditing;
using Rabits.Domain.Auth;
using Rabits.Domain.Engagement;
using Rabits.Domain.Operations;

namespace Rabits.Mcp;

/// <summary>
/// Defines the Rabits capabilities exposed as MCP tools. Every tool runs through the exact same
/// engine and authorization gate as the CLI — intrusive tools still require an in-scope,
/// intrusive-enabled engagement, so exposing them to an agent does not remove the guardrail.
/// </summary>
public static class RabitsToolset
{
    public static IReadOnlyList<ToolDefinition> Build() => new List<ToolDefinition>
    {
        new("wifi_scan",
            "Passively scan for nearby Wi-Fi networks (SSID, BSSID, RSSI, channel, encryption).",
            SchemaObject(),
            async (sp, _, ct) =>
            {
                var networks = await sp.GetRequiredService<ScanWirelessNetworksHandler>().HandleAsync(ct);
                return networks.Select(n => new
                {
                    ssid = n.Ssid, hidden = n.IsHidden, bssid = n.Bssid.ToString(),
                    rssiDbm = n.Rssi.Dbm, channel = n.Channel.Number, band = n.Channel.Band.ToString(),
                    encryption = n.Encryption.ToString(),
                });
            }),

        new("hosts_discover",
            "ACTIVE host discovery over a CIDR/IP (ICMP + ARP) with optional TCP port scan. Requires the range to be in the engagement scope.",
            SchemaObject(
                Prop("target", "string", "Target CIDR (10.0.0.0/24) or single IP.", required: true),
                Prop("ports", "string", "Port profile: none | common | top100 | artillery.")),
            (sp, args, ct) => Guarded(async () =>
            {
                var request = new HostDiscoveryRequest
                {
                    Target = GetString(args, "target"),
                    Ports = ParseProfile(GetString(args, "ports", "none")),
                };
                var hosts = await sp.GetRequiredService<DiscoverHostsHandler>().HandleAsync(request, cancellationToken: ct);
                return hosts.Select(h => new
                {
                    ip = h.Address.ToString(), status = h.Status.ToString(), mac = h.Mac?.ToString(),
                    vendor = h.Vendor, latencyMs = h.Latency?.TotalMilliseconds,
                    openPorts = h.OpenPorts.Select(p => new { p.Number, p.Service }),
                });
            })),

        new("web_dns", "Passive DNS record lookup for a domain.",
            SchemaObject(Prop("domain", "string", "Domain name.", required: true)),
            async (sp, args, ct) =>
            {
                var records = await sp.GetRequiredService<DnsReconHandler>().HandleAsync(GetString(args, "domain"), cancellationToken: ct);
                return records.Select(r => new { type = r.Type.ToString(), value = r.Value, ttl = r.Ttl });
            }),

        new("web_whois", "Passive WHOIS lookup for a domain.",
            SchemaObject(Prop("domain", "string", "Domain name.", required: true)),
            async (sp, args, ct) =>
            {
                var w = await sp.GetRequiredService<WhoisHandler>().HandleAsync(GetString(args, "domain"), ct);
                return new { w.Query, w.Server, w.Registrar, w.CreatedOn, w.ExpiresOn, w.DaysUntilExpiry, w.NameServers };
            }),

        new("web_subdomains", "Passive subdomain enumeration for a domain (DNS-based).",
            SchemaObject(Prop("domain", "string", "Domain name.", required: true)),
            async (sp, args, ct) =>
            {
                var found = await sp.GetRequiredService<EnumerateSubdomainsHandler>()
                    .HandleAsync(GetString(args, "domain"), cancellationToken: ct);
                return found.Select(s => new { s.Name, s.Addresses });
            }),

        new("web_headers",
            "ACTIVE HTTP/TLS inspection + security-header audit of a URL. Requires the host to be in scope.",
            SchemaObject(Prop("url", "string", "Target URL.", required: true)),
            (sp, args, ct) => Guarded(async () =>
            {
                var info = await sp.GetRequiredService<InspectWebEndpointHandler>().HandleAsync(GetString(args, "url"), ct);
                return new
                {
                    url = info.Url.ToString(), status = info.StatusCode, server = info.Server,
                    tls = info.Tls is null ? null : new { info.Tls.Subject, info.Tls.Issuer, info.Tls.NotAfter, info.Tls.ChainValid, info.Tls.DaysUntilExpiry },
                    security = info.SecurityFindings.Select(f => new { f.Header, f.Present, severity = f.Severity.ToString(), f.Detail }),
                };
            })),

        new("web_secrets", "Statically hunt for burned-in secrets in a page and its scripts (passive).",
            SchemaObject(Prop("url", "string", "Page URL to scan.", required: true)),
            async (sp, args, ct) =>
            {
                if (!Uri.TryCreate(GetString(args, "url"), UriKind.Absolute, out var uri))
                    return new { error = "invalid url" };
                var findings = await sp.GetRequiredService<ScanUrlForSecretsHandler>().HandleAsync(uri, ct);
                return findings.Select(f => new { f.RuleName, f.Category, severity = f.Severity.ToString(), match = f.RedactedMatch, f.Source });
            }),

        new("credential_audit",
            "INTRUSIVE dictionary credential audit against an HTTP login. Requires the host to be in scope AND the engagement to permit intrusive actions; otherwise refused.",
            SchemaObject(
                Prop("url", "string", "Login endpoint URL.", required: true),
                Prop("username", "string", "Username to test.", required: true),
                Prop("successStatus", "integer", "HTTP status indicating success (e.g. 302)."),
                Prop("failContains", "string", "Response body text that indicates failure."),
                ArrayProp("passwords", "Passwords to try (defaults to the embedded common list).")),
            (sp, args, ct) => Guarded(async () =>
            {
                var passwords = GetStringArray(args, "passwords");
                var request = new CredentialAuditRequest
                {
                    Target = new AuthTarget
                    {
                        Protocol = AuthProtocol.HttpForm,
                        Url = new Uri(GetString(args, "url")),
                        SuccessStatusCodes = GetInt(args, "successStatus") is { } s ? new[] { s } : Array.Empty<int>(),
                        FailureBodyContains = args.TryGetProperty("failContains", out var fc) ? fc.GetString() : null,
                    },
                    Usernames = new[] { GetString(args, "username") },
                    Passwords = passwords.Count > 0 ? passwords : sp.GetRequiredService<ICredentialWordlist>().Passwords,
                };
                var summary = await sp.GetRequiredService<CredentialAuditHandler>().HandleAsync(request, cancellationToken: ct);
                return new
                {
                    summary.Attempted, summary.Failures, summary.Errors, summary.StoppedEarly,
                    successes = summary.Successes.Select(c => new { c.Username, c.Password }),
                };
            })),

        new("engagement_scope",
            "Show the current engagement scope: what targets and operation classes are authorized.",
            SchemaObject(),
            (sp, _, _) =>
            {
                var godMode = sp.GetRequiredService<AuthorizationOptions>().BypassScope;
                var scope = sp.GetRequiredService<IScopePolicy>().Current;
                object result = new
                {
                    godMode,
                    note = godMode ? "GOD MODE — scope validation disabled; all operations are authorized (still audited)." : null,
                    loaded = scope is not null,
                    scope = scope is null ? null : Describe(scope),
                };
                return Task.FromResult(result);
            }),

        new("scope_authorize",
            "Record an operator authorization to expand the engagement scope in real time (no restart). "
            + "Use this when the operator states a target is authorized (e.g. 'you may test 10.0.0.5'). "
            + "The rule type is inferred; pass classification to raise what is permitted (passive|active|intrusive). Audited.",
            SchemaObject(
                Prop("target", "string", "Target to authorize: IP, CIDR, domain, MAC/BSSID or SSID.", required: true),
                Prop("classification", "string", "Max operation class to permit: passive | active | intrusive.")),
            async (sp, args, ct) =>
            {
                var target = GetString(args, "target");
                if (target.Length == 0) return new { error = "target is required" };

                var rule = ScopeRule.ForTarget(target);
                var raiseTo = ParseClassification(GetString(args, "classification"));
                var scope = sp.GetRequiredService<IScopePolicy>().Authorize(rule, raiseTo);

                await sp.GetRequiredService<IAuditLog>().RecordAsync(
                    RabitsOperation.Passive("scope.authorize", target), AuditOutcome.Completed,
                    $"authorized {rule.Type} '{rule.Pattern}'" + (raiseTo is { } c ? $"; max→{c}" : string.Empty), ct);

                return new { authorized = new { type = rule.Type.ToString(), pattern = rule.Pattern }, scope = Describe(scope) };
            }),

        new("scope_revoke",
            "Remove an authorization from the engagement scope by its pattern. Audited.",
            SchemaObject(Prop("pattern", "string", "Exact rule pattern to remove.", required: true)),
            async (sp, args, ct) =>
            {
                var pattern = GetString(args, "pattern");
                var policy = sp.GetRequiredService<IScopePolicy>();
                var removed = policy.Revoke(pattern);
                if (removed)
                    await sp.GetRequiredService<IAuditLog>().RecordAsync(
                        RabitsOperation.Passive("scope.revoke", pattern), AuditOutcome.Completed, $"revoked '{pattern}'", ct);

                return new { removed, scope = policy.Current is { } s ? Describe(s) : null };
            }),

        new("audit_trail", "Show the tamper-evident engagement audit trail and whether its hash chain is intact.",
            SchemaObject(),
            async (sp, _, ct) =>
            {
                var audit = sp.GetRequiredService<IAuditLog>();
                var entries = await audit.ReadAllAsync(ct);
                var intact = await audit.VerifyAsync(ct);
                return new
                {
                    chainIntact = intact, count = entries.Count,
                    entries = entries.TakeLast(50).Select(e => new
                    {
                        e.Sequence, e.Timestamp, operation = e.OperationName,
                        classification = e.Classification.ToString(), e.Target, outcome = e.Outcome.ToString(), e.Detail,
                    }),
                };
            }),
    };

    // ── argument helpers ──────────────────────────────────────────────────────────────────────
    private static async Task<object> Guarded(Func<Task<object>> action)
    {
        try { return await action(); }
        catch (OutOfScopeException ex) { return new { refused = true, reason = ex.Message }; }
        catch (ArgumentException ex) { return new { error = ex.Message }; }
    }

    private static string GetString(JsonElement args, string name, string fallback = "")
        => args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? fallback : fallback;

    private static int? GetInt(JsonElement args, string name)
        => args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var v) && v.TryGetInt32(out var i) ? i : null;

    private static IReadOnlyList<string> GetStringArray(JsonElement args, string name)
    {
        if (args.ValueKind == JsonValueKind.Object && args.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array)
            return v.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!).ToList();
        return Array.Empty<string>();
    }

    private static PortScanProfile ParseProfile(string value) => value.ToLowerInvariant() switch
    {
        "common" => PortScanProfile.Common,
        "top100" => PortScanProfile.Top100,
        "artillery" => PortScanProfile.Artillery,
        _ => PortScanProfile.None,
    };

    private static OperationClassification? ParseClassification(string value) => value.ToLowerInvariant() switch
    {
        "passive" => OperationClassification.Passive,
        "active" => OperationClassification.Active,
        "intrusive" => OperationClassification.Intrusive,
        _ => null,
    };

    private static object Describe(EngagementScope scope) => new
    {
        name = scope.Name,
        maxClassification = scope.MaxClassification.ToString(),
        startsAt = scope.StartsAt,
        endsAt = scope.EndsAt,
        maxRequestsPerSecond = scope.MaxRequestsPerSecond,
        rules = scope.Rules.Select(r => new { type = r.Type.ToString(), pattern = r.Pattern }),
    };

    // ── JSON-Schema builders ──────────────────────────────────────────────────────────────────
    private static object SchemaObject(params (string Name, object Schema, bool Required)[] props)
    {
        var properties = props.ToDictionary(p => p.Name, p => p.Schema);
        var required = props.Where(p => p.Required).Select(p => p.Name).ToArray();
        return required.Length > 0
            ? new { type = "object", properties, required }
            : new { type = "object", properties };
    }

    private static (string, object, bool) Prop(string name, string type, string description, bool required = false)
        => (name, new { type, description }, required);

    private static (string, object, bool) ArrayProp(string name, string description)
        => (name, new { type = "array", items = new { type = "string" }, description }, false);
}
