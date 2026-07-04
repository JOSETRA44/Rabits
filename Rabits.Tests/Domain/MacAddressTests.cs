using Rabits.Domain.Networking;

namespace Rabits.Tests.Domain;

public class MacAddressTests
{
    [Theory]
    [InlineData("3C:5A:B4:11:22:33")]
    [InlineData("3c-5a-b4-11-22-33")]
    public void Parses_colon_and_hyphen_forms(string input)
    {
        var mac = MacAddress.Parse(input);
        Assert.Equal("3C:5A:B4:11:22:33", mac.ToString());
    }

    [Fact]
    public void Exposes_oui_from_first_three_octets()
        => Assert.Equal("3C:5A:B4", MacAddress.Parse("3C:5A:B4:11:22:33").Oui);

    [Theory]
    [InlineData("not-a-mac")]
    [InlineData("3C:5A:B4:11:22")]
    [InlineData("")]
    public void Rejects_malformed_input(string input)
    {
        Assert.False(MacAddress.TryParse(input, out _));
        Assert.Throws<InvalidMacAddressException>(() => MacAddress.Parse(input));
    }

    [Fact]
    public void Has_value_equality()
        => Assert.Equal(MacAddress.Parse("AA:BB:CC:DD:EE:FF"), MacAddress.Parse("aa:bb:cc:dd:ee:ff"));

    [Fact]
    public void Detects_broadcast_address()
        => Assert.True(MacAddress.Parse("FF:FF:FF:FF:FF:FF").IsBroadcast);
}
