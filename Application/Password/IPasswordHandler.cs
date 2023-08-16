using Application.Password.Data;

namespace Application.Password;

public interface IPasswordHandler
{
    EncryptedPassword Encrypt(string password);

    bool Decrypt(string password, string hash, string salt);
}