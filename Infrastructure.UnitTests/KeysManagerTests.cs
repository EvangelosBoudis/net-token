using System.Text.RegularExpressions;
using Infrastructure.Keys;
using Infrastructure.UnitTests.Utils;

namespace Infrastructure.UnitTests;

public partial class KeysManagerTests
{
    private readonly TestUtil _util = new();

    private readonly KeysManager _manager = new();

    [GeneratedRegex("^(?:[A-Z2-7]+=*|=(?:3[TJKPSW]|4[FSY]|5[V]|6[BE]|7A)?=*$)$")]
    private static partial Regex Base32Regex();

    [Fact]
    public void GenerateRandomBase32Key_ReturnsValidKey()
    {
        // Act
        var key = _manager.GenerateRandomBase32Key();

        // Assert
        Assert.NotNull(key);
        Assert.Matches(Base32Regex(), key);
    }

    [Fact]
    public void GenerateTotpCode_ReturnsValidTotpCode()
    {
        // Act
        var code = _manager.GenerateTotpCode();

        // Assert
        Assert.NotNull(code);
        Assert.True(code.Content.Length is >= 6 and <= 8);
    }

    [Fact]
    public void GenerateTotpUri_ReturnsValidTotpUri()
    {
        // Arrange
        var email = _util.Email;
        var issuer = _util.TokenOptions.Issuer;
        var key = _manager.GenerateRandomBase32Key();

        // Act
        var uri = _manager.GenerateTotpUri(key, email, issuer);

        // Assert
        Assert.True(Uri.TryCreate(uri, UriKind.Absolute, out var parsedUri));
        Assert.Equal("otpauth", parsedUri.Scheme);
        Assert.Equal("totp", parsedUri.Host);
    }

    [Fact]
    public void ValidateTotpCode_ValidCode_ReturnsTrue()
    {
        // Arrange
        var key = _manager.GenerateRandomBase32Key();
        var code = _manager.GenerateTotpCode(key);

        // Act
        var isValid = _manager.ValidateTotpCode(key, code.Content);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void ValidateTotpCode_InvalidCode_ReturnsFalse()
    {
        // Arrange
        var key = _manager.GenerateRandomBase32Key();
        var code = _util.Otp;

        // Act
        var isValid = _manager.ValidateTotpCode(key, code);

        // Assert
        Assert.False(isValid);
    }
}