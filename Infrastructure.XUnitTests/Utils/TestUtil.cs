using System.Reflection;
using Application.Token.Data;
using Domain.Entities;
using Newtonsoft.Json;

namespace Infrastructure.XUnitTests.Utils;

public class TestUtil
{
    public User User { get; }

    public TokenOptions TokenOptions { get; }

    public string InvalidAccessToken { get; }

    public TestUtil()
    {
        var stream = Assembly
            .GetExecutingAssembly()
            .GetManifestResourceStream("Infrastructure.XUnitTests.Utils.mock.json")!;

        using var reader = new StreamReader(stream);
        var json = reader.ReadToEnd();
        var data = JsonConvert.DeserializeObject<MockData>(json)!;

        User = new User
        {
            Id = new Guid(),
            Username = data.User.Name,
            Email = data.User.Email,
            PhoneNumber = data.User.Phone,
            PhoneNumberConfirmed = false,
            TwoFactorAuth = new TwoFactorAuth
            {
                Enabled = false,
                AuthenticatorKey = data.User.AuthenticatorKey
            },
            PasswordHash = data.User.Hash,
            PasswordSalt = data.User.Salt,
            Account = new Account()
        };

        TokenOptions = data.Token;

        InvalidAccessToken = data.InvalidAccessToken;
    }
}