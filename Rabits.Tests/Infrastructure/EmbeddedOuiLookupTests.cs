using Microsoft.Extensions.Logging.Abstractions;
using Rabits.Domain.Networking;
using Rabits.Infrastructure.Hosts;

namespace Rabits.Tests.Infrastructure;

public class EmbeddedOuiLookupTests
{
    private static EmbeddedOuiLookup Lookup()
        => new(externalFilePath: null, NullLogger<EmbeddedOuiLookup>.Instance);

    [Fact]
    public void Loads_the_embedded_starter_set()
        => Assert.True(Lookup().EntryCount > 0);

    [Fact]
    public void Resolves_a_known_oui_regardless_of_the_low_octets()
    {
        var vendor = Lookup().Lookup(MacAddress.Parse("00:0C:29:AB:CD:EF")); // VMware
        Assert.NotNull(vendor);
        Assert.Contains("VMware", vendor);
    }

    [Fact]
    public void Returns_null_for_an_unknown_oui()
        => Assert.Null(Lookup().Lookup(MacAddress.Parse("12:34:56:78:9A:BC")));
}
