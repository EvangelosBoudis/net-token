namespace Application.Token.Data;

public class TokenOptions
{
    public required string Audience { get; set; } = string.Empty;

    public required string Issuer { get; set; } = string.Empty;

    public required string SecretKey { get; set; } = string.Empty;

    public required int AccessExpirationInMinutes { get; set; }

    public required int RefreshExpirationInDays { get; set; }
}