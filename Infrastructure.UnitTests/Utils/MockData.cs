using Application.Notification.Data;
using Application.Token.Data;

namespace Infrastructure.UnitTests.Utils;

public record MockData(
    string Name,
    string Email,
    string Phone,
    string Otp,
    string Password,
    string Hash,
    string Salt,
    string AuthenticatorKey,
    string InvalidAccessToken,
    MailOptions Mail,
    TokenOptions Token);