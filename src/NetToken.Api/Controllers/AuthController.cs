using Application.Authentication;
using Application.Authentication.Data;
using Domain.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace NetToken.Api.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("sign-up")]
    public async Task<IActionResult> SignUp([FromBody] SignUpDto request)
    {
        await _authService.SignUpAsync(request);
        return Ok();
    }

    [HttpPost("confirm-sign-up")]
    public async Task<IActionResult> ConfirmSignUp([FromBody] ConfirmSignUpDto request)
    {
        await _authService.ConfirmSignUpAsync(request);
        return Ok();
    }

    [HttpPost("resend-sign-up-code")]
    public async Task<IActionResult> ResendSignUpCode([FromBody] ResendSignUpCodeDto request)
    {
        await _authService.ResendSignUpCodeAsync(request);
        return Ok();
    }

    [HttpPost("sign-in")]
    public async Task<IActionResult> SignIn([FromBody] SignInDto request)
    {
        var result = await _authService.SignInAsync(request);
        return Ok(result);
    }

    [HttpPost("two-factor-sign-in")]
    public async Task<IActionResult> TwoFactorSignIn([FromBody] TwoFactorSignInDto request)
    {
        var result = await _authService.TwoFactorSignInAsync(request);
        return Ok(result);
    }

    [HttpPut("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto request)
    {
        await _authService.ResetPasswordAsync(request);
        return Ok();
    }

    [HttpPut("confirm-reset-password")]
    public async Task<IActionResult> ConfirmResetPassword([FromBody] ConfirmResetPasswordDto request)
    {
        await _authService.ConfirmResetPasswordAsync(request);
        return Ok();
    }

    [Authorize, HttpPut("modify-password")]
    public async Task<IActionResult> ModifyPassword([FromBody] ModifyPasswordDto request)
    {
        await _authService.ModifyPasswordAsync(User, request);
        return Ok();
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenData request)
    {
        var token = await _authService.RefreshTokenAsync(request);
        return Ok(token);
    }

    [Authorize, HttpPost("revoke-token")]
    public async Task<IActionResult> RevokeToken()
    {
        await _authService.RevokeRefreshTokensAsync(User);
        return Ok();
    }

    [Authorize, HttpPost("activate-two-factor-auth")]
    public async Task<IActionResult> ActivateTwoFactorAuth()
    {
        await _authService.ActivateTwoFactorAuthAsync(User);
        return Ok();
    }

    [HttpPost("confirm-two-factor-auth-activation")]
    public async Task<IActionResult> ConfirmTwoFactorAuthActivation(
        [FromBody] ConfirmTwoFactorAuthActivationDto request)
    {
        await _authService.ConfirmTwoFactorAuthActivationAsync(User, request);
        return Ok();
    }

    [Authorize, HttpPost("deactivate-two-factor-auth")]
    public async Task<IActionResult> DeactivateTwoFactorAuth(DeactivateTwoFactorAuthDto dto)
    {
        await _authService.DeactivateTwoFactorAuthAsync(User, dto);
        return Ok();
    }
}