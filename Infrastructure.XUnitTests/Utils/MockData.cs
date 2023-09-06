namespace Infrastructure.XUnitTests.Utils;

public record MockData(
    string Username,
    string Email,
    string PhoneNumber,
    string PasswordHash,
    string PasswordSalt,
    string AuthenticatorKey,
    string InvalidAccessToken,
    string Audience,
    string Issuer,
    string SecretKey,
    int AccessExpirationInMinutes,
    int RefreshExpirationInDays);