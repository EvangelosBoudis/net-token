using System.Security.Cryptography;
using System.Text;
using Application.Password;
using Application.Password.Data;

namespace Infrastructure.Password;

public class PasswordHandler : IPasswordHandler
{
    private const int KeySize = 64;
    private const int Iterations = 350000;
    private static readonly HashAlgorithmName HashAlgorithm = HashAlgorithmName.SHA512;

    public EncryptedPassword Encrypt(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(KeySize);
        var bPassword = Encoding.UTF8.GetBytes(password);

        var hash = Rfc2898DeriveBytes.Pbkdf2(bPassword, salt, Iterations, HashAlgorithm, KeySize);

        return new EncryptedPassword(Convert.ToHexString(hash), Convert.ToHexString(salt));
    }

    public bool Decrypt(string password, string hash, string salt)
    {
        var bSalt = Convert.FromHexString(salt);

        var masterHash = Rfc2898DeriveBytes.Pbkdf2(password, bSalt, Iterations, HashAlgorithm, KeySize);

        return CryptographicOperations.FixedTimeEquals(masterHash, Convert.FromHexString(hash));
    }
}