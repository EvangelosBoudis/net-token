namespace Domain.Exceptions;

public static class ErrorCode
{
    public const string IncorrectCode = "INCORRECT_CODE";
    public const string ExpiredCode = "EXPIRED_CODE";

    public const string IncorrectKey = "INCORRECT_KEY";
    public const string ExpiredKey = "EXPIRED_KEY";

    public const string IncorrectEmail = "INCORRECT_EMAIL";
    public const string IncorrectPassword = "INCORRECT_PASSWORD";
    public const string IncorrectEmailOrPassword = "INCORRECT_EMAIL_OR_PASSWORD";

    public const string InvalidToken = "INVALID_TOKEN";
    public const string ExpiredToken = "EXPIRED_TOKEN";

    public const string LockedAccount = "LOCKED_ACCOUNT";
    public const string UnconfirmedAccount = "UNCONFIRMED_ACCOUNT";
    public const string AlreadyConfirmedAccount = "ALREADY_CONFIRMED_ACCOUNT";

    public const string AlreadyActivatedTwoFactorAuth = "ALREADY_ACTIVATED_TWO_FACTOR_AUTH";
    public const string NotActivatedTwoFactorAuth = "NOT_ACTIVATED_TWO_FACTOR_AUTH";
    public const string EmptyAuthenticatorKey = "EMPTY_AUTHENTICATOR_KEY";

    public const string InvalidUsernameOrEmail = "INVALID_USERNAME_OR_EMAIL";
    public const string InvalidBodyRequest = "INVALID_BODY_REQUEST";
}