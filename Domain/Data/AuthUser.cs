namespace Domain.Data;

public record AuthUser(
    Guid Id,
    string Email,
    string Name,
    string PhoneNumber,
    bool PhoneNumberVerified,
    bool TwoFactorEnabled);