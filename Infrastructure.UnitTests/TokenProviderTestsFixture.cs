using System.Text.RegularExpressions;
using Application.Token;
using Infrastructure.Token;
using Microsoft.Extensions.Options;
using Application.Token.Exceptions;
using Infrastructure.UnitTests.Utils;

namespace Infrastructure.UnitTests;

[TestFixture]
public partial class TokenProviderTestsFixture
{
    private TestUtil _util;

    [GeneratedRegex("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")]
    private static partial Regex Base64Regex();

    [SetUp]
    public void Setup()
    {
        _util = new TestUtil();
    }

    [Test]
    public void ReadAccessToken_InvalidAccessToken_ThrowsInvalidTokenException()
    {
        // Arrange
        var options = Options.Create(_util.TokenOptions);
        ITokenProvider provider = new TokenProvider(options);

        // Act & Assert
        Assert.Throws<InvalidTokenException>(() => provider.ReadAccessToken(_util.InvalidAccessToken));
    }

    [Test]
    public void CreateAccessToken_ValidUser_ReturnsValidAccessToken()
    {
        // Arrange
        var options = Options.Create(_util.TokenOptions);
        ITokenProvider provider = new TokenProvider(options);

        // Act
        var accessToken = provider.CreateAccessToken(_util.User);

        // Assert
        var token = provider.ReadAccessToken(accessToken);
        Assert.Multiple(() =>
        {
            Assert.That(token.Subject, Is.EqualTo(_util.User.Id.ToString()));
            Assert.That(token.Issuer, Is.EqualTo(options.Value.Issuer));
            Assert.That(token.Audience, Is.EqualTo(options.Value.Audience));
            Assert.That(token.ValidFrom, Is.EqualTo(token.IssuedAt));
            Assert.That(token.ValidTo, Is.EqualTo(token.IssuedAt.AddMinutes(options.Value.AccessExpirationInMinutes)));
            Assert.That(token.UniqueName, Is.EqualTo(_util.User.Username));
            Assert.That(token.Email, Is.EqualTo(_util.User.Email));
            Assert.That(token.PhoneNumber, Is.EqualTo(_util.User.PhoneNumber));
            Assert.That(token.PhoneNumberVerified, Is.EqualTo(_util.User.PhoneNumberConfirmed));
            Assert.That(token.TwoFactorEnabled, Is.EqualTo(_util.User.TwoFactorAuth?.Enabled));
        });
    }

    [Test]
    public void CreateRefreshToken_ReturnsValidRefreshToken()
    {
        // Arrange
        var options = Options.Create(_util.TokenOptions);
        ITokenProvider provider = new TokenProvider(options);

        // Act
        var refreshToken = provider.CreateRefreshToken();

        // Assert
        Assert.That(Base64Regex().IsMatch(refreshToken), Is.True);
    }
}