namespace Application.Token.Exceptions;

public class InvalidTokenException : TokenException
{
    public InvalidTokenException(string token) : base(Domain.Exceptions.ErrorCode.InvalidToken, token)
    {
    }
}