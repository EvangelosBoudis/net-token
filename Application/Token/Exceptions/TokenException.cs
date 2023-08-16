namespace Application.Token.Exceptions;

public class TokenException : SystemException
{
    public string ErrorCode { get; }

    public string Token { get; }

    protected TokenException(string errorCode, string token)
    {
        ErrorCode = errorCode;
        Token = token;
    }
}