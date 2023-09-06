namespace Application.Token.Data;

public record TokenDetails(
    string Subject,
    string Issuer,
    DateTime IssuedAt,
    string Audience,
    DateTime ValidFrom,
    DateTime ValidTo,
    string SignatureAlgorithm,
    string UniqueName,
    string Email,
    string PhoneNumber,
    bool PhoneNumberVerified,
    bool TwoFactorEnabled);