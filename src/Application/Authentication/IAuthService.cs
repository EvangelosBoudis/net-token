using System.Security.Claims;
using Application.Authentication.Data;
using Domain.Data;

namespace Application.Authentication;

public interface IAuthService
{
    Task SignUpAsync(SignUpDto dto);

    Task ConfirmSignUpAsync(ConfirmSignUpDto dto);

    Task ResendSignUpCodeAsync(ResendSignUpCodeDto dto);

    Task<SignInResult> SignInAsync(SignInDto dto);

    Task<SignInResult> TwoFactorSignInAsync(TwoFactorSignInDto dto);

    Task ResetPasswordAsync(ResetPasswordDto dto);

    Task ConfirmResetPasswordAsync(ConfirmResetPasswordDto dto);

    Task ModifyPasswordAsync(AuthUser auth, ModifyPasswordDto dto);

    Task ModifyPasswordAsync(ClaimsPrincipal principal, ModifyPasswordDto dto);

    Task<TokenData> RefreshTokenAsync(TokenData token);

    Task RevokeRefreshTokensAsync(AuthUser auth);

    Task RevokeRefreshTokensAsync(ClaimsPrincipal principal);

    Task ActivateTwoFactorAuthAsync(AuthUser auth);

    Task ActivateTwoFactorAuthAsync(ClaimsPrincipal principal);

    Task ConfirmTwoFactorAuthActivationAsync(AuthUser auth, ConfirmTwoFactorAuthActivationDto dto);

    Task ConfirmTwoFactorAuthActivationAsync(ClaimsPrincipal principal, ConfirmTwoFactorAuthActivationDto dto);

    Task DeactivateTwoFactorAuthAsync(AuthUser auth, DeactivateTwoFactorAuthDto dto);

    Task DeactivateTwoFactorAuthAsync(ClaimsPrincipal principal, DeactivateTwoFactorAuthDto dto);
}