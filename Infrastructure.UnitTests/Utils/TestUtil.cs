using System.Reflection;
using Application.Token.Data;
using Domain.Entities;
using Newtonsoft.Json;

namespace Infrastructure.UnitTests.Utils;

public class TestUtil
{
    public TokenOptions TokenOptions { get; }

    public User User { get; }

    public string InvalidAccessToken { get; }

    public TestUtil()
    {
        var stream = Assembly
            .GetExecutingAssembly()
            .GetManifestResourceStream("Infrastructure.UnitTests.Utils.mock.json")!;

        using var reader = new StreamReader(stream);
        var json = reader.ReadToEnd();
        var mock = JsonConvert.DeserializeObject<MockData>(json)!;

        TokenOptions = new TokenOptions
        {
            Audience = mock.Audience,
            Issuer = mock.Issuer,
            SecretKey = mock.SecretKey,
            AccessExpirationInMinutes = mock.AccessExpirationInMinutes,
            RefreshExpirationInDays = mock.RefreshExpirationInDays
        };

        User = new User
        {
            Id = new Guid(),
            Username = mock.Username,
            Email = mock.Email,
            PhoneNumber = mock.PhoneNumber,
            PhoneNumberConfirmed = false,
            TwoFactorAuth = new TwoFactorAuth
            {
                Enabled = false,
                AuthenticatorKey = mock.AuthenticatorKey
            },
            PasswordHash = mock.PasswordHash,
            PasswordSalt = mock.PasswordSalt,
            Account = new Account()
        };

        InvalidAccessToken = mock.InvalidAccessToken;
    }
}