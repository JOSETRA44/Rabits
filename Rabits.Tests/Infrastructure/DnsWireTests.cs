using Rabits.Domain.Recon;
using Rabits.Infrastructure.Recon;

namespace Rabits.Tests.Infrastructure;

public class DnsWireTests
{
    [Fact]
    public void Builds_a_well_formed_query_header_and_question()
    {
        var query = DnsWire.BuildQuery(0x1234, "example.com", DnsRecordType.A);

        Assert.Equal(0x12, query[0]);
        Assert.Equal(0x34, query[1]);
        Assert.Equal(0x01, query[2]);           // recursion desired flag high byte
        Assert.Equal(0x00, query[4]);           // QDCOUNT high
        Assert.Equal(0x01, query[5]);           // QDCOUNT low = 1
        Assert.Equal(7, query[12]);             // first label length "example"
    }

    [Fact]
    public void Parses_an_answer_that_uses_a_compression_pointer()
    {
        var response = BuildResponse();

        var (rcode, records) = DnsWire.Parse(response, DnsRecordType.A);

        Assert.Equal(0, rcode);
        var record = Assert.Single(records);
        Assert.Equal(DnsRecordType.A, record.Type);
        Assert.Equal("93.184.216.34", record.Value);
        Assert.Equal(600u, record.Ttl);
    }

    [Fact]
    public void Reads_a_compressed_name()
    {
        var response = BuildResponse();
        // The answer's name at offset 29 is a pointer (0xC0 0x0C) back to the question name.
        var name = DnsWire.ReadName(response, 29, out _);
        Assert.Equal("example.com", name);
    }

    private static byte[] BuildResponse() => new byte[]
    {
        // Header
        0x12, 0x34,             // id
        0x81, 0x80,             // flags: response, RD, RA, no error
        0x00, 0x01,             // QDCOUNT
        0x00, 0x01,             // ANCOUNT
        0x00, 0x00,             // NSCOUNT
        0x00, 0x00,             // ARCOUNT
        // Question: example.com A IN
        0x07, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
        0x03, (byte)'c', (byte)'o', (byte)'m',
        0x00,
        0x00, 0x01,             // QTYPE A
        0x00, 0x01,             // QCLASS IN
        // Answer
        0xC0, 0x0C,             // name pointer -> offset 12
        0x00, 0x01,             // type A
        0x00, 0x01,             // class IN
        0x00, 0x00, 0x02, 0x58, // TTL 600
        0x00, 0x04,             // RDLENGTH 4
        0x5D, 0xB8, 0xD8, 0x22, // 93.184.216.34
    };
}
