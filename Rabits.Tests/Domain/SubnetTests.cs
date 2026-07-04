using System.Net;
using Rabits.Domain.Networking;

namespace Rabits.Tests.Domain;

public class SubnetTests
{
    [Fact]
    public void Parses_cidr_and_masks_network_address()
    {
        var subnet = Subnet.Parse("10.1.2.200/24");
        Assert.Equal("10.1.2.0", subnet.NetworkAddress.ToString());
        Assert.Equal(24, subnet.PrefixLength);
    }

    [Fact]
    public void Bare_ip_is_a_host_route()
    {
        var subnet = Subnet.Parse("192.168.1.5");
        Assert.Equal(32, subnet.PrefixLength);
        Assert.Equal("192.168.1.5", subnet.NetworkAddress.ToString());
    }

    [Theory]
    [InlineData("10.0.0.0/24", "10.0.0.55", true)]
    [InlineData("10.0.0.0/24", "10.0.1.55", false)]
    public void Contains_address(string cidr, string ip, bool expected)
        => Assert.Equal(expected, Subnet.Parse(cidr).Contains(IPAddress.Parse(ip)));

    [Theory]
    [InlineData("10.0.0.0/16", "10.0.5.0/24", true)]
    [InlineData("10.0.0.0/24", "10.0.0.0/16", false)]
    [InlineData("10.0.0.0/24", "10.0.0.0/24", true)]
    public void Contains_subnet(string outer, string inner, bool expected)
        => Assert.Equal(expected, Subnet.Parse(outer).Contains(Subnet.Parse(inner)));

    [Theory]
    [InlineData("10.0.0.0/24", 254)]
    [InlineData("10.0.0.0/30", 2)]
    [InlineData("10.0.0.0/31", 2)]
    [InlineData("10.0.0.5/32", 1)]
    public void Enumerates_usable_hosts(string cidr, int expectedCount)
        => Assert.Equal(expectedCount, Subnet.Parse(cidr).EnumerateHosts().Count());

    [Fact]
    public void Enumeration_excludes_network_and_broadcast_for_wide_networks()
    {
        var hosts = Subnet.Parse("192.168.1.0/29").EnumerateHosts().Select(h => h.ToString()).ToList();
        Assert.DoesNotContain("192.168.1.0", hosts);   // network
        Assert.DoesNotContain("192.168.1.7", hosts);   // broadcast
        Assert.Contains("192.168.1.1", hosts);
        Assert.Contains("192.168.1.6", hosts);
    }

    [Fact]
    public void Enumeration_is_bounded_by_max_hosts()
        => Assert.Equal(10, Subnet.Parse("10.0.0.0/16").EnumerateHosts(maxHosts: 10).Count());
}
