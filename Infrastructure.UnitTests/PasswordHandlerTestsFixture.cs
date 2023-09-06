using Infrastructure.Password;
using System.Text.RegularExpressions;
using Application.Password;

namespace Infrastructure.UnitTests;

[TestFixture]
public partial class PasswordHandlerTests
{
    [GeneratedRegex("^[0-9a-fA-F]{128}$")]
    private static partial Regex Sha512Regex();

    [GeneratedRegex("^[0-9a-fA-F]+$")]
    private static partial Regex HexadecimalRegex();

    [Test]
    public void Encrypt_ValidPassword_ReturnsValidEncryptedPassword()
    {
        // Arrange
        IPasswordHandler handler = new PasswordHandler();
        const string password = "secure-password";

        // Act
        var encrypted = handler.Encrypt(password);

        // Assert
        Assert.Multiple(() =>
        {
            Assert.That(encrypted, Is.Not.Null);

            Assert.That(encrypted.Hash, Is.Not.Null);
            Assert.That(Sha512Regex().IsMatch(encrypted.Hash), Is.True);

            Assert.That(encrypted.Salt, Is.Not.Null);
            Assert.That(HexadecimalRegex().IsMatch(encrypted.Salt), Is.True);
        });
    }

    [Test]
    public void Decrypt_CorrectPassword_ReturnsTrue()
    {
        // Arrange
        IPasswordHandler handler = new PasswordHandler();
        const string password = "secure-password";
        var encrypted = handler.Encrypt(password);

        // Act
        var isCorrect = handler.Decrypt(password, encrypted.Hash, encrypted.Salt);

        // Assert
        Assert.That(isCorrect, Is.True);
    }

    [Test]
    public void Decrypt_IncorrectPassword_ReturnsFalse()
    {
        // Arrange
        IPasswordHandler handler = new PasswordHandler();
        const string password = "secure-password";
        var encrypted = handler.Encrypt(password);
        const string incorrect = "incorrect-password";

        // Act
        var isCorrect = handler.Decrypt(incorrect, encrypted.Hash, encrypted.Salt);

        // Assert
        Assert.That(isCorrect, Is.False);
    }
}