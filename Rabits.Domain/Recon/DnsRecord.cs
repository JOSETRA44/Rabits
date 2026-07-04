namespace Rabits.Domain.Recon;

/// <summary>DNS resource record types Rabits can query.</summary>
public enum DnsRecordType
{
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
}

/// <summary>A single DNS resource record: its type, presentation value, and TTL (seconds).</summary>
public sealed record DnsRecord(DnsRecordType Type, string Value, uint Ttl)
{
    public override string ToString() => $"{Type,-6} {Value}";
}
