using Application.Keys;
using Application.Keys.Data;
using OtpNet;

namespace Infrastructure.Keys;

public class KeysManager : IKeysManager
{
    public string GenerateRandomBase32Key()
    {
        var key = KeyGeneration.GenerateRandomKey(20);
        return Base32Encoding.ToString(key);
    }

    public TotpCode GenerateTotpCode()
    {
        var key = GenerateRandomBase32Key();
        return GenerateTotpCode(key);
    }

    public TotpCode GenerateTotpCode(string key)
    {
        var authKey = Base32Encoding.ToBytes(key);
        var issuedAt = DateTime.UtcNow;
        var code = new Totp(authKey).ComputeTotp(issuedAt);
        return new TotpCode(code, issuedAt);
    }

    public string GenerateTotpUri(string key, string email, string issuer)
    {
        var otp = new OtpUri(OtpType.Totp, key, email, issuer);
        return otp.ToString()!;
    }

    public bool ValidateTotpCode(string key, string totpCode)
    {
        var authKey = Base32Encoding.ToBytes(key);
        return new Totp(authKey).VerifyTotp(DateTime.UtcNow, totpCode, out _);
    }
}