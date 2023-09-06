using System.Text.RegularExpressions;
using Application.Keys;
using Infrastructure.Keys;

namespace Infrastructure.UnitTests;

[TestFixture]
public partial class KeysManagerTestsFixture
{
    [GeneratedRegex("^(?:[A-Z2-7]+=*|=(?:3[TJKPSW]|4[FSY]|5[V]|6[BE]|7A)?=*$)$")]
    private static partial Regex Base32Regex();

    [Test]
    public void GenerateRandomBase32Key_ReturnsValidKey()
    {
        // Arrange
        IKeysManager manager = new KeysManager();

        // Act
        var key = manager.GenerateRandomBase32Key();

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(key, Is.Not.Null);
            Assert.That(Base32Regex().IsMatch(key), Is.True);
        });
    }

    [Test]
    public void GenerateTotpCode_ReturnsValidTotpCode()
    {
        // Arrange
        IKeysManager manager = new KeysManager();

        // Act
        var code = manager.GenerateTotpCode();

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(code, Is.Not.Null);
            Assert.That(code.Length is >= 6 and <= 8, Is.True);
        });
    }

    [Test]
    public void GenerateTotpUri_ReturnsValidTotpUri()
    {
        // Arrange
        IKeysManager manager = new KeysManager();
        var key = manager.GenerateRandomBase32Key();
        const string email = "john.deo@corp.com";
        const string issuer = "super-app";

        // Act
        var uri = manager.GenerateTotpUri(key, email, issuer);

        // Assert
        var isValid = Uri.TryCreate(uri, UriKind.Absolute, out var parsedUri);
        Assert.Multiple(() =>
        {
            Assert.That(isValid, Is.True);
            Assert.That(parsedUri?.Scheme, Is.EqualTo("otpauth"));
            Assert.That(parsedUri?.Host, Is.EqualTo("totp"));
        });
    }

    [Test]
    public void ValidateTotpCode_ValidCode_ReturnsTrue()
    {
        // Arrange
        IKeysManager manager = new KeysManager();
        var key = manager.GenerateRandomBase32Key();
        var code = manager.GenerateTotpCode(key);

        // Act
        var isValid = manager.ValidateTotpCode(key, code);

        // Assert
        Assert.That(isValid, Is.True);
    }

    [Test]
    public void ValidateTotpCode_InvalidCode_ReturnsFalse()
    {
        // Arrange
        IKeysManager keysManager = new KeysManager();
        var key = keysManager.GenerateRandomBase32Key();
        const string invalidCode = "123456";

        // Act
        var isValid = keysManager.ValidateTotpCode(key, invalidCode);

        // Assert
        Assert.That(isValid, Is.False);
    }
}