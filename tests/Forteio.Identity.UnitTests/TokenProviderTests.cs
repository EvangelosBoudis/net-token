using System.Text.RegularExpressions;
using Application.Token.Exceptions;
using Forteio.Identity.Token;
using Forteio.Identity.UnitTests.Utils;
using Microsoft.Extensions.Options;

namespace Forteio.Identity.UnitTests;

public partial class TokenProviderTests
{
    private readonly TestUtil _util;

    private readonly TokenProvider _provider;

    [GeneratedRegex("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")]
    private static partial Regex Base64Regex();

    public TokenProviderTests()
    {
        _util = new TestUtil();
        _provider = new TokenProvider(Options.Create(_util.TokenOptions));
    }

    [Fact]
    public void ReadAccessToken_InvalidAccessToken_ThrowsInvalidTokenException()
    {
        // Arrange
        var token = _util.InvalidAccessToken;

        // Act & Assert
        Assert.Throws<InvalidTokenException>(() => _provider.ReadAccessToken(token));
    }

    [Fact]
    public void CreateAccessToken_ValidUser_ReturnsValidAccessToken()
    {
        // Arrange
        var user = _util.User;
        var options = _util.TokenOptions;

        // Act
        var accessToken = _provider.CreateAccessToken(user);
        var token = _provider.ReadAccessToken(accessToken);

        // Assert
        Assert.Equal(user.Id.ToString(), token.Subject);
        Assert.Equal(options.Issuer, token.Issuer);
        Assert.Equal(options.Audience, token.Audience);
        Assert.Equal(token.IssuedAt, token.ValidFrom);
        Assert.Equal(token.IssuedAt.AddMinutes(options.AccessExpirationInMinutes), token.ValidTo);
        Assert.Equal(user.Username, token.UniqueName);
        Assert.Equal(user.Email, token.Email);
        Assert.Equal(user.PhoneNumber, token.PhoneNumber);
        Assert.Equal(user.PhoneNumberConfirmed, token.PhoneNumberVerified);
        Assert.Equal(user.TwoFactorAuth?.Enabled, token.TwoFactorEnabled);
    }

    [Fact]
    public void CreateRefreshToken_ReturnsValidRefreshToken()
    {
        // Act
        var refreshToken = _provider.CreateRefreshToken();

        // Assert
        Assert.Matches(Base64Regex(), refreshToken);
    }
}