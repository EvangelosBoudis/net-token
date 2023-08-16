namespace Application.Password.Data;

public record EncryptedPassword(string Hash, string Salt);