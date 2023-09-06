using System.Text.RegularExpressions;
using Application.Token;
using Application.Token.Data;
using Application.Token.Exceptions;
using Infrastructure.Token;
using Infrastructure.XUnitTests.Utils;
using Microsoft.Extensions.Options;

namespace Infrastructure.XUnitTests;

public partial class TokenProviderTests
{
    private readonly TestUtil _utils;
    private readonly IOptions<TokenOptions> _options;
    private readonly ITokenProvider _provider;

    [GeneratedRegex("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")]
    private static partial Regex Base64Regex();

    public TokenProviderTests()
    {
        _utils = new TestUtil();
        _options = Options.Create(_utils.TokenOptions);
        _provider = new TokenProvider(_options);
    }

    [Fact]
    public void ReadAccessToken_InvalidAccessToken_ThrowsInvalidTokenException()
    {
        Assert.Throws<InvalidTokenException>(() => _provider.ReadAccessToken(_utils.InvalidAccessToken));
    }

    [Fact]
    public void CreateAccessToken_ValidUser_ReturnsValidAccessToken()
    {
        var user = _utils.User;
        var accessToken = _provider.CreateAccessToken(user);
        var token = _provider.ReadAccessToken(accessToken);

        Assert.Equal(user.Id.ToString(), token.Subject);
        Assert.Equal(_options.Value.Issuer, token.Issuer);
        Assert.Equal(_options.Value.Audience, token.Audience);
        Assert.Equal(token.IssuedAt, token.ValidFrom);
        Assert.Equal(token.IssuedAt.AddMinutes(_options.Value.AccessExpirationInMinutes), token.ValidTo);
        Assert.Equal(user.Username, token.UniqueName);
        Assert.Equal(user.Email, token.Email);
        Assert.Equal(user.PhoneNumber, token.PhoneNumber);
        Assert.Equal(user.PhoneNumberConfirmed, token.PhoneNumberVerified);
        Assert.Equal(user.TwoFactorAuth?.Enabled, token.TwoFactorEnabled);
    }

    [Fact]
    public void CreateRefreshToken_ReturnsValidRefreshToken()
    {
        var refreshToken = _provider.CreateRefreshToken();

        Assert.Matches(Base64Regex(), refreshToken);
    }
}