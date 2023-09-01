using Infrastructure.Password;
using System.Text.RegularExpressions;

namespace Infrastructure.UnitTests;

[TestFixture]
public partial class PasswordHandlerTests
{
    private PasswordHandler _handler;

    [GeneratedRegex("^[0-9a-fA-F]{128}$")]
    private static partial Regex Sha512Regex();

    [GeneratedRegex("^[0-9a-fA-F]+$")]
    private static partial Regex HexadecimalRegex();

    [SetUp]
    public void Setup()
    {
        _handler = new PasswordHandler();
    }

    [Test]
    public void Encrypt_ValidPassword_ReturnsValidEncryptedPassword()
    {
        // Arrange
        const string password = "secure-password";

        // Act
        var encrypted = _handler.Encrypt(password);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(encrypted, Is.Not.Null);
            Assert.That(Sha512Regex().IsMatch(encrypted.Hash), Is.True);
            Assert.That(HexadecimalRegex().IsMatch(encrypted.Salt), Is.True);
        });
    }

    [Test]
    public void Decrypt_CorrectPassword_ReturnsTrue()
    {
        // Arrange
        const string password = "secure-password";
        var encrypted = _handler.Encrypt(password);

        // Act
        var isCorrect = _handler.Decrypt(password, encrypted.Hash, encrypted.Salt);

        // Assert
        Assert.That(isCorrect, Is.True);
    }

    [Test]
    public void Decrypt_IncorrectPassword_ReturnsFalse()
    {
        // Arrange
        const string password = "secure-password";
        var encrypted = _handler.Encrypt(password);
        const string incorrect = "incorrect-password";

        // Act
        var isCorrect = _handler.Decrypt(incorrect, encrypted.Hash, encrypted.Salt);

        // Assert
        Assert.That(isCorrect, Is.False);
    }
}