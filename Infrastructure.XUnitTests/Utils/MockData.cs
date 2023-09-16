using Application.Notification.Data;
using Application.Token.Data;

namespace Infrastructure.XUnitTests.Utils;

public record MockUser(string Name, string Email, string Phone, string Hash, string Salt, string AuthenticatorKey);

public record MockData(MockUser User, MailOptions Mail, TokenOptions Token, string InvalidAccessToken);