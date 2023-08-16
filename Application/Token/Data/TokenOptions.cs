namespace Application.Token.Data;

public class TokenOptions
{
    public string Audience { get; set; } = string.Empty;

    public string Issuer { get; set; } = string.Empty;

    public string SecretKey { get; set; } = string.Empty;

    public int AccessExpirationInMinutes { get; set; } = 0;

    public int RefreshExpirationInDays { get; set; } = 0;
}