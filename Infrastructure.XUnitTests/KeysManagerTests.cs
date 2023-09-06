using System.Text.RegularExpressions;
using Application.Keys;
using Infrastructure.Keys;

namespace Infrastructure.XUnitTests;

public partial class KeysManagerTests
{
    private readonly IKeysManager _manager = new KeysManager();

    [GeneratedRegex("^(?:[A-Z2-7]+=*|=(?:3[TJKPSW]|4[FSY]|5[V]|6[BE]|7A)?=*$)$")]
    private static partial Regex Base32Regex();

    [Fact]
    public void GenerateRandomBase32Key_ReturnsValidKey()
    {
        var key = _manager.GenerateRandomBase32Key();

        Assert.NotNull(key);
        Assert.Matches(Base32Regex(), key);
    }

    [Fact]
    public void GenerateTotpCode_ReturnsValidTotpCode()
    {
        var code = _manager.GenerateTotpCode();

        Assert.NotNull(code);
        Assert.True(code.Length is >= 6 and <= 8);
    }

    [Fact]
    public void GenerateTotpUri_ReturnsValidTotpUri()
    {
        var key = _manager.GenerateRandomBase32Key();

        var uri = _manager.GenerateTotpUri(key, "john.deo@corp.com", "super-app");

        var isValid = Uri.TryCreate(uri, UriKind.Absolute, out var parsedUri);

        Assert.True(isValid);
        Assert.Equal("otpauth", parsedUri?.Scheme);
        Assert.Equal("totp", parsedUri?.Host);
    }

    [Fact]
    public void ValidateTotpCode_ValidCode_ReturnsTrue()
    {
        var key = _manager.GenerateRandomBase32Key();
        var code = _manager.GenerateTotpCode(key);

        var isValid = _manager.ValidateTotpCode(key, code);

        Assert.True(isValid);
    }

    [Fact]
    public void ValidateTotpCode_InvalidCode_ReturnsFalse()
    {
        var key = _manager.GenerateRandomBase32Key();

        var isValid = _manager.ValidateTotpCode(key, "123456");

        Assert.False(isValid);
    }
}