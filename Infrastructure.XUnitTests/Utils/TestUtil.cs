using System.Reflection;
using Application.Notification.Data;
using Application.Token.Data;
using Domain.Entities;
using Newtonsoft.Json;

namespace Infrastructure.XUnitTests.Utils;

public class TestUtil
{
    public string Name { get; }

    public string Email { get; }

    public string Phone { get; }

    public string Otp { get; }

    public string Password { get; }

    public string Hash { get; }

    public string Salt { get; }

    public string AuthenticatorKey { get; }
    public string InvalidAccessToken { get; }

    public MailOptions MailOptions { get; }

    public TokenOptions TokenOptions { get; }

    public User User { get; }

    public TestUtil()
    {
        var stream = Assembly
            .GetExecutingAssembly()
            .GetManifestResourceStream("Infrastructure.XUnitTests.Utils.mock.json")!;

        using var reader = new StreamReader(stream);
        var json = reader.ReadToEnd();
        var data = JsonConvert.DeserializeObject<MockData>(json)!;

        Name = data.Name;
        Email = data.Email;
        Phone = data.Phone;
        Otp = data.Otp;
        Password = data.Password;
        Hash = data.Hash;
        Salt = data.Salt;
        AuthenticatorKey = data.AuthenticatorKey;
        InvalidAccessToken = data.InvalidAccessToken;
        MailOptions = data.Mail;
        TokenOptions = data.Token;

        User = new User
        {
            Id = new Guid(),
            Username = data.Name,
            Email = data.Email,
            PhoneNumber = data.Phone,
            TwoFactorAuth = new TwoFactorAuth
            {
                AuthenticatorKey = data.AuthenticatorKey
            },
            PasswordHash = data.Hash,
            PasswordSalt = data.Salt,
            Account = new Account()
        };
    }
}