using System.Text.RegularExpressions;
using Forteio.Identity.Password;
using Forteio.Identity.UnitTests.Utils;

namespace Forteio.Identity.UnitTests;

public partial class PasswordHandlerTests
{
    private readonly TestUtil _util = new();

    private readonly PasswordHandler _handler = new();

    [GeneratedRegex("^[0-9a-fA-F]{128}$")]
    private static partial Regex Sha512Regex();

    [GeneratedRegex("^[0-9a-fA-F]+$")]
    private static partial Regex HexadecimalRegex();

    [Fact]
    public void Encrypt_ValidPassword_ReturnsValidEncryptedPassword()
    {
        // Arrange
        var password = _util.Password;

        // Act
        var encrypted = _handler.Encrypt(password);

        // Assert
        Assert.NotNull(encrypted);
        Assert.NotNull(encrypted.Hash);
        Assert.Matches(Sha512Regex(), encrypted.Hash);
        Assert.NotNull(encrypted.Salt);
        Assert.Matches(HexadecimalRegex(), encrypted.Salt);
    }

    [Fact]
    public void Decrypt_CorrectPassword_ReturnsTrue()
    {
        // Arrange
        var password = _util.Password;
        var encrypted = _handler.Encrypt(password);

        // Act
        var isCorrect = _handler.Decrypt(password, encrypted.Hash, encrypted.Salt);

        // Assert
        Assert.True(isCorrect);
    }

    [Fact]
    public void Decrypt_IncorrectPassword_ReturnsFalse()
    {
        // Arrange
        var password = _util.Password;
        var encrypted = _handler.Encrypt(password);
        const string otherPassword = "comeIN123@@";

        // Act
        var isCorrect = _handler.Decrypt(otherPassword, encrypted.Hash, encrypted.Salt);

        // Assert
        Assert.False(isCorrect);
    }
}