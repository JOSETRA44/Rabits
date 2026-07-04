using System.Net;
using System.Text;
using Rabits.Domain.Recon;

namespace Rabits.Infrastructure.Recon;

/// <summary>
/// Minimal DNS wire-format encoder/decoder (RFC 1035): builds a standard recursive query and
/// parses the answer section, including name-compression pointers. No external dependencies.
/// </summary>
internal static class DnsWire
{
    public static byte[] BuildQuery(ushort id, string name, DnsRecordType type)
    {
        var buffer = new List<byte>(32);
        WriteUInt16(buffer, id);
        WriteUInt16(buffer, 0x0100); // standard query, recursion desired
        WriteUInt16(buffer, 1);      // QDCOUNT
        WriteUInt16(buffer, 0);      // ANCOUNT
        WriteUInt16(buffer, 0);      // NSCOUNT
        WriteUInt16(buffer, 0);      // ARCOUNT

        WriteName(buffer, name);
        WriteUInt16(buffer, (ushort)type);
        WriteUInt16(buffer, 1);      // QCLASS = IN

        return buffer.ToArray();
    }

    /// <summary>Parses a response and returns the answer records that match <paramref name="wanted"/>.</summary>
    public static (int Rcode, IReadOnlyList<DnsRecord> Records) Parse(byte[] data, DnsRecordType wanted)
    {
        var records = new List<DnsRecord>();
        var offset = 0;

        ReadUInt16(data, ref offset);              // id
        var flags = ReadUInt16(data, ref offset);
        var rcode = flags & 0x0F;
        var qd = ReadUInt16(data, ref offset);
        var an = ReadUInt16(data, ref offset);
        ReadUInt16(data, ref offset);              // ns
        ReadUInt16(data, ref offset);              // ar

        for (var i = 0; i < qd; i++)
        {
            ReadName(data, offset, out offset);
            offset += 4; // qtype + qclass
        }

        for (var i = 0; i < an && offset < data.Length; i++)
        {
            ReadName(data, offset, out offset);
            var type = (DnsRecordType)ReadUInt16(data, ref offset);
            ReadUInt16(data, ref offset);          // class
            var ttl = ReadUInt32(data, ref offset);
            var rdLength = ReadUInt16(data, ref offset);
            var rdataStart = offset;

            var value = ReadRData(data, type, rdataStart, rdLength);
            if (type == wanted && value is not null)
                records.Add(new DnsRecord(type, value, ttl));

            offset = rdataStart + rdLength;
        }

        return (rcode, records);
    }

    private static string? ReadRData(byte[] data, DnsRecordType type, int start, int length)
    {
        switch (type)
        {
            case DnsRecordType.A when length == 4:
                return new IPAddress(data[start..(start + 4)]).ToString();
            case DnsRecordType.AAAA when length == 16:
                return new IPAddress(data[start..(start + 16)]).ToString();
            case DnsRecordType.CNAME:
            case DnsRecordType.NS:
            case DnsRecordType.PTR:
                return ReadName(data, start, out _);
            case DnsRecordType.MX:
            {
                var pos = start;
                var preference = ReadUInt16(data, ref pos);
                var exchange = ReadName(data, pos, out _);
                return $"{preference} {exchange}";
            }
            case DnsRecordType.TXT:
            {
                var sb = new StringBuilder();
                var pos = start;
                while (pos < start + length)
                {
                    int len = data[pos++];
                    if (pos + len > start + length) break;
                    sb.Append(Encoding.UTF8.GetString(data, pos, len));
                    pos += len;
                }
                return sb.ToString();
            }
            case DnsRecordType.SOA:
            {
                var pos = start;
                var mname = ReadName(data, pos, out pos);
                var rname = ReadName(data, pos, out pos);
                var serial = ReadUInt32(data, ref pos);
                return $"{mname} {rname} serial={serial}";
            }
            default:
                return null;
        }
    }

    public static void WriteName(List<byte> buffer, string name)
    {
        foreach (var label in name.Trim().TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            buffer.Add((byte)bytes.Length);
            buffer.AddRange(bytes);
        }
        buffer.Add(0);
    }

    public static string ReadName(byte[] data, int start, out int next)
    {
        var sb = new StringBuilder();
        var i = start;
        var jumped = false;
        var safety = 0;
        next = start;

        while (i < data.Length)
        {
            int len = data[i];
            if (len == 0)
            {
                i++;
                if (!jumped) next = i;
                break;
            }

            if ((len & 0xC0) == 0xC0)
            {
                var pointer = ((len & 0x3F) << 8) | data[i + 1];
                if (!jumped) next = i + 2;
                jumped = true;
                i = pointer;
                if (++safety > 255) break; // guard against pointer loops
                continue;
            }

            sb.Append(Encoding.ASCII.GetString(data, i + 1, len)).Append('.');
            i += 1 + len;
            if (!jumped) next = i;
        }

        return sb.ToString().TrimEnd('.');
    }

    private static void WriteUInt16(List<byte> buffer, ushort value)
    {
        buffer.Add((byte)(value >> 8));
        buffer.Add((byte)(value & 0xFF));
    }

    private static ushort ReadUInt16(byte[] data, ref int offset)
    {
        var value = (ushort)((data[offset] << 8) | data[offset + 1]);
        offset += 2;
        return value;
    }

    private static uint ReadUInt32(byte[] data, ref int offset)
    {
        var value = ((uint)data[offset] << 24) | ((uint)data[offset + 1] << 16)
                    | ((uint)data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
        return value;
    }
}
