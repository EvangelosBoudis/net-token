using System.Text.RegularExpressions;
using Application.Token.Exceptions;
using Domain.Entities;
using Infrastructure.Token;
using Infrastructure.XUnitTests.Utils;
using Microsoft.Extensions.Options;

namespace Infrastructure.XUnitTests;

public partial class TokenProviderTests
{
    private readonly TokenProvider _provider;

    private readonly MockData _dataMock;

    [GeneratedRegex("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")]
    private static partial Regex Base64Regex();

    public TokenProviderTests()
    {
        _dataMock = new TestUtil().MockData;
        _provider = new TokenProvider(Options.Create(_dataMock.Token));
    }

    [Fact]
    public void ReadAccessToken_InvalidAccessToken_ThrowsInvalidTokenException()
    {
        // Arrange
        var token = _dataMock.User.InvalidAccessToken;

        // Act & Assert
        Assert.Throws<InvalidTokenException>(() => _provider.ReadAccessToken(token));
    }

    [Fact]
    public void CreateAccessToken_ValidUser_ReturnsValidAccessToken()
    {
        // Arrange
        var user = new User
        {
            Id = new Guid(),
            Username = _dataMock.User.Name,
            Email = _dataMock.User.Email,
            PhoneNumber = _dataMock.User.Phone,
            PhoneNumberConfirmed = false,
            TwoFactorAuth = new TwoFactorAuth
            {
                Enabled = false,
                AuthenticatorKey = _dataMock.User.AuthenticatorKey
            },
            PasswordHash = _dataMock.User.Hash,
            PasswordSalt = _dataMock.User.Salt,
            Account = new Account()
        };

        var options = _dataMock.Token;

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