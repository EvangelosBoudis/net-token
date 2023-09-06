using System.Text.RegularExpressions;
using Application.Password;
using Infrastructure.Password;

namespace Infrastructure.XUnitTests;

public partial class PasswordHandlerTests
{
    private readonly IPasswordHandler _handler = new PasswordHandler();

    [GeneratedRegex("^[0-9a-fA-F]{128}$")]
    private static partial Regex Sha512Regex();

    [GeneratedRegex("^[0-9a-fA-F]+$")]
    private static partial Regex HexadecimalRegex();

    [Fact]
    public void Encrypt_ValidPassword_ReturnsValidEncryptedPassword()
    {
        const string password = "comeIN123";

        var encrypted = _handler.Encrypt(password);

        Assert.NotNull(encrypted);
        Assert.NotNull(encrypted.Hash);
        Assert.Matches(Sha512Regex(), encrypted.Hash);
        Assert.NotNull(encrypted.Salt);
        Assert.Matches(HexadecimalRegex(), encrypted.Salt);
    }

    [Fact]
    public void Decrypt_CorrectPassword_ReturnsTrue()
    {
        const string password = "comeIN123";
        var encrypted = _handler.Encrypt(password);

        var isCorrect = _handler.Decrypt(password, encrypted.Hash, encrypted.Salt);

        Assert.True(isCorrect);
    }

    [Fact]
    public void Decrypt_IncorrectPassword_ReturnsFalse()
    {
        const string password = "comeIN123";
        var encrypted = _handler.Encrypt(password);
        const string incorrect = "comeIN123@@";

        var isCorrect = _handler.Decrypt(incorrect, encrypted.Hash, encrypted.Salt);

        Assert.False(isCorrect);
    }
}