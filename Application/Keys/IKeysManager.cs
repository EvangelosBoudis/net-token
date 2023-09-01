namespace Application.Keys;

public interface IKeysManager
{
    public string GenerateRandomBase32Key();

    public string GenerateTotpCode();

    public string GenerateTotpCode(string key);

    public string GenerateTotpUri(string key, string email, string issuer);

    public bool ValidateTotpCode(string key, string totpCode);
}