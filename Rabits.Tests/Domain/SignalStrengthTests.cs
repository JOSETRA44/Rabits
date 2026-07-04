using Rabits.Domain.Networking;

namespace Rabits.Tests.Domain;

public class SignalStrengthTests
{
    [Theory]
    [InlineData(-50, 100)]
    [InlineData(-75, 50)]
    [InlineData(-100, 0)]
    [InlineData(-30, 100)] // clamped
    public void Maps_dbm_to_quality(int dbm, int expectedQuality)
        => Assert.Equal(expectedQuality, SignalStrength.FromDbm(dbm).QualityPercent);

    [Theory]
    [InlineData(-40, 4)]
    [InlineData(-60, 3)]
    [InlineData(-70, 2)]
    [InlineData(-85, 1)]
    [InlineData(-95, 0)]
    public void Maps_dbm_to_bars(int dbm, int expectedBars)
        => Assert.Equal(expectedBars, SignalStrength.FromDbm(dbm).Bars);

    [Fact]
    public void Stronger_signal_compares_greater()
        => Assert.True(SignalStrength.FromDbm(-40).CompareTo(SignalStrength.FromDbm(-80)) > 0);
}
