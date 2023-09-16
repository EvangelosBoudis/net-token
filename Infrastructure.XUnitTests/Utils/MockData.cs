using Application.Notification.Data;
using Application.Token.Data;

namespace Infrastructure.XUnitTests.Utils;

public record MockUser(
    string Name,
    string Email,
    string Phone,
    string Password,
    string Otp,
    string Hash,
    string Salt,
    string AuthenticatorKey,
    string InvalidAccessToken);

public record MockData(MockUser User, MailOptions Mail, TokenOptions Token);