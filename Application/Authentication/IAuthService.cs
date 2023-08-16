using Application.Authentication.Data;
using Domain.Data;

namespace Application.Authentication;

public interface IAuthService
{
    Task SignUpAsync(SignUpDto dto);

    Task ConfirmSignUpAsync(ConfirmSignUpDto dto);

    Task ResendSignUpCodeAsync(ResendSignUpCodeDto dto);

    Task<SignInResult> SignInAsync(SignInDto dto);

    Task<SignInResult> TwoFactorSignAsync(TwoFactorSignInDto dto);

    Task ResetPasswordAsync(ResetPasswordDto dto);

    Task ConfirmResetPasswordAsync(ConfirmResetPasswordDto dto);

    Task ModifyPasswordAsync(AuthUser auth, ModifyPasswordDto dto);

    Task<TokenData> RefreshTokenAsync(TokenData token);

    Task RevokeRefreshTokensAsync(AuthUser auth);

    Task ActivateTwoFactorAuthAsync(AuthUser auth);

    Task ConfirmTwoFactorAuthActivationAsync(AuthUser auth, ConfirmTwoFactorAuthActivationDto dto);

    Task DeactivateTwoFactorAuthAsync(AuthUser auth, DeactivateTwoFactorAuthDto dto);
}