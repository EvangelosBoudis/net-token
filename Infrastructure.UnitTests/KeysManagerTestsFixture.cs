using System.Text.RegularExpressions;
using Infrastructure.Keys;

namespace Infrastructure.UnitTests;

[TestFixture]
public partial class KeysManagerTestsFixture
{
    private KeysManager keysManager;

    [GeneratedRegex("^[A-Z2-7]+=*$")]
    private static partial Regex Base64Regex();

    [SetUp]
    public void Setup()
    {
        keysManager = new KeysManager();
    }

    [Test]
    public void GenerateRandomBase32Key_ReturnsValidKey()
    {
        // Act
        var key = keysManager.GenerateRandomBase32Key();

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(key, Is.Not.Null);
            Assert.That(Base64Regex().IsMatch(key), Is.True);
        });
    }

    [Test]
    public void GenerateTotpCode_ReturnsValidTotpCode()
    {
        // Act
        var code = keysManager.GenerateTotpCode();

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
        var key = keysManager.GenerateRandomBase32Key();
        const string email = "john.deo@corp.com";
        const string issuer = "super-app";

        // Act
        var uri = keysManager.GenerateTotpUri(key, email, issuer);

        // Assert
        Assert.That(uri, Is.Not.Null);

        var isValid = Uri.TryCreate(uri, UriKind.Absolute, out var parsedUri);
        Assert.Multiple(() =>
        {
            Assert.That(isValid, Is.True);
            Assert.That(parsedUri!.Scheme, Is.EqualTo("otpauth"));
            Assert.That(parsedUri.Host, Is.EqualTo("totp"));
        });
    }

    [Test]
    public void ValidateTotpCode_ValidCode_ReturnsTrue()
    {
        // Arrange
        var key = keysManager.GenerateRandomBase32Key();
        var code = keysManager.GenerateTotpCode(key);

        // Act
        var isValid = keysManager.ValidateTotpCode(key, code);

        // Assert
        Assert.That(isValid, Is.True);
    }

    [Test]
    public void ValidateTotpCode_InvalidCode_ReturnsFalse()
    {
        // Arrange
        var key = keysManager.GenerateRandomBase32Key();
        const string invalidCode = "123456"; // An invalid code

        // Act
        var isValid = keysManager.ValidateTotpCode(key, invalidCode);

        // Assert
        Assert.That(isValid, Is.False);
    }
}