namespace Application.Authentication.Exceptions;

public class AuthException : Exception
{
    public string ErrorCode { get; }

    public AuthException(string errorCode, string? description = null)
        : base(description)
    {
        ErrorCode = errorCode;
    }
}