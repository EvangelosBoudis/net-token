using System.Security.Claims;
using Application.Authentication;
using Application.Authentication.Data;
using Application.Authentication.Exceptions;
using Application.Keys;
using Application.Notification;
using Application.Notification.Data;
using Application.Password;
using Application.Repository;
using Application.Token;
using Application.Token.Data;
using Domain.Data;
using Domain.Entities;
using Domain.Enums;
using Domain.Exceptions;
using Infrastructure.Authentication.Extensions;
using Infrastructure.Store;
using Microsoft.Extensions.Options;

namespace Infrastructure.Authentication;

public class AuthService : IAuthService
{
    private readonly DataContext _context;
    private readonly TokenOptions _options;

    private readonly IKeysManager _keysManager;
    private readonly ITokenProvider _tokenProvider;
    private readonly IPasswordHandler _passwordHandler;
    private readonly INotificationSender _notificationSender;

    private readonly IUserRepository _userRepository;
    private readonly IOtpRepository _otpRepository;
    private readonly IChallengeRepository _challengeRepository;
    private readonly IRefreshTokenRepository _refreshTokenRepository;

    public AuthService(
        DataContext context,
        IOptions<TokenOptions> options,
        IKeysManager keysManager,
        ITokenProvider tokenProvider,
        IPasswordHandler passwordHandler,
        INotificationSender notificationSender,
        IUserRepository userRepository,
        IOtpRepository otpRepository,
        IChallengeRepository challengeRepository,
        IRefreshTokenRepository refreshTokenRepository)
    {
        _context = context;
        _options = options.Value;
        _keysManager = keysManager;
        _tokenProvider = tokenProvider;
        _passwordHandler = passwordHandler;
        _notificationSender = notificationSender;
        _userRepository = userRepository;
        _otpRepository = otpRepository;
        _challengeRepository = challengeRepository;
        _refreshTokenRepository = refreshTokenRepository;
    }

    public async Task SignUpAsync(SignUpDto dto)
    {
        var exists = await _userRepository.ExistsByUsernameOrEmailAsync(dto.Username, dto.Email);
        if (exists) throw new AuthException(ErrorCode.InvalidUsernameOrEmail);

        var code = _keysManager.GenerateTotpCode();
        var encrypted = _passwordHandler.Encrypt(dto.Password);

        var user = new User
        {
            Username = dto.Username,
            Email = dto.Email,
            PasswordHash = encrypted.Hash,
            PasswordSalt = encrypted.Salt,
            Account = new Account(),
            OneTimePasswords = new List<Otp>
            {
                new()
                {
                    Code = code,
                    Type = OtpType.RegisterAccount,
                    ExpiredAt = DateTime.UtcNow.AddMinutes(5)
                }
            }
        };

        await _userRepository.SaveAndFlushAsync(user);

        var email = new EmailDto(dto.Email, "Email Confirmation", code);
        await _notificationSender.SendEmailAsync(email);
    }

    public async Task ConfirmSignUpAsync(ConfirmSignUpDto dto)
    {
        var user = await _userRepository.FindByEmailAsync(dto.Email);
        if (user is null) throw new AuthException(ErrorCode.IncorrectEmail);
        if (user.Account.Confirmed) throw new AuthException(ErrorCode.AlreadyConfirmedAccount);

        var code = await _otpRepository.FindByUserIdCodeAndTypeAsync(
            user.Id, dto.ConfirmationCode, OtpType.RegisterAccount);
        if (code is null) throw new AuthException(ErrorCode.IncorrectCode);
        if (code.ExpiredAt < DateTime.UtcNow) throw new AuthException(ErrorCode.ExpiredCode);

        code.Redeemed = true;
        user.EmailConfirmed = true;
        user.Account.Confirmed = true;

        await _context.SaveChangesAsync();
    }

    public async Task ResendSignUpCodeAsync(ResendSignUpCodeDto dto)
    {
        var user = await _userRepository.FindByEmailAsync(dto.Email);
        if (user is null) throw new AuthException(ErrorCode.IncorrectEmail);
        if (user.Account.Confirmed) throw new AuthException(ErrorCode.AlreadyConfirmedAccount);

        await _otpRepository.UpdateAsDisabledActiveCodesAsync(user.Id, OtpType.RegisterAccount);

        var code = _keysManager.GenerateTotpCode();

        user.OneTimePasswords.Add(new Otp
        {
            Code = code,
            Type = OtpType.RegisterAccount,
            ExpiredAt = DateTime.UtcNow.AddMinutes(5)
        });

        await _context.SaveChangesAsync();

        var email = new EmailDto(dto.Email, "Email Confirmation", code);
        await _notificationSender.SendEmailAsync(email);
    }

    public async Task<SignInResult> SignInAsync(SignInDto dto)
    {
        var user = await _userRepository.FindByEmailAsync(dto.Email);
        if (user is null) throw new AuthException(ErrorCode.IncorrectEmailOrPassword);
        if (!user.Account.Confirmed) throw new AuthException(ErrorCode.UnconfirmedAccount);
        if (user.Account.Locked && user.Account.LockEndAt > DateTime.UtcNow)
            throw new AuthException(ErrorCode.LockedAccount);

        var matched = _passwordHandler.Decrypt(dto.Password, user.PasswordHash, user.PasswordSalt);

        user.Account.FailedAccessAttempts = matched ? 0 : user.Account.FailedAccessAttempts + 1;
        user.Account.Locked = user.Account.FailedAccessAttempts >= 5;
        user.Account.LockEndAt = user.Account.Locked ? DateTime.UtcNow.AddMinutes(5) : null;

        if (!matched)
        {
            await _context.SaveChangesAsync();
            throw new AuthException(ErrorCode.IncorrectEmailOrPassword);
        }

        if (user.TwoFactorAuth is { Enabled: true })
        {
            var key = _keysManager.GenerateSha1Key();

            user.TwoFactorAuth.Challenges.Add(new Challenge
            {
                Key = key,
                ExpiredAt = DateTime.UtcNow.AddMinutes(2)
            });

            await _context.SaveChangesAsync();

            return new SignInResult(ChallengeKey: key, SignedIn: false);
        }

        var token = _tokenProvider.Generate(user);

        user.RefreshTokens.Add(new RefreshToken
        {
            Value = token.RefreshToken,
            ExpiredAt = DateTime.UtcNow.AddDays(_options.RefreshExpirationInDays)
        });

        await _context.SaveChangesAsync();

        return new SignInResult(token);
    }

    public async Task<SignInResult> TwoFactorSignAsync(TwoFactorSignInDto dto)
    {
        var challenge = await _challengeRepository.FindByKeyAsync(dto.ChallengeKey);
        if (challenge is null) throw new AuthException(ErrorCode.IncorrectKey);
        if (challenge.ExpiredAt < DateTime.UtcNow) throw new AuthException(ErrorCode.ExpiredKey);
        if (challenge.TwoFactorAuth.User.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);

        var matched = _keysManager.ValidateTotpCode(challenge.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode);
        if (!matched) throw new AuthException(ErrorCode.IncorrectCode);

        challenge.Redeemed = true;

        var token = _tokenProvider.Generate(challenge.TwoFactorAuth.User);

        challenge.TwoFactorAuth.User.RefreshTokens.Add(new RefreshToken
        {
            Value = token.RefreshToken,
            ExpiredAt = DateTime.UtcNow.AddDays(_options.RefreshExpirationInDays)
        });

        await _context.SaveChangesAsync();

        return new SignInResult(token);
    }

    public async Task ResetPasswordAsync(ResetPasswordDto dto)
    {
        var user = await _userRepository.FindByEmailAsync(dto.Email);
        if (user is null) throw new AuthException(ErrorCode.IncorrectEmail);
        if (user.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);
        if (!user.Account.Confirmed) throw new AuthException(ErrorCode.UnconfirmedAccount);

        await _otpRepository.UpdateAsDisabledActiveCodesAsync(user.Id, OtpType.ResetPassword);

        var code = _keysManager.GenerateTotpCode();

        user.OneTimePasswords.Add(new Otp
        {
            Code = code,
            Type = OtpType.ResetPassword,
            ExpiredAt = DateTime.UtcNow.AddMinutes(5)
        });

        await _context.SaveChangesAsync();

        var email = new EmailDto(dto.Email, "Email Confirmation", code);
        await _notificationSender.SendEmailAsync(email);
    }

    public async Task ConfirmResetPasswordAsync(ConfirmResetPasswordDto dto)
    {
        var user = await _userRepository.FindByEmailAsync(dto.Email);
        if (user is null) throw new AuthException(ErrorCode.IncorrectEmail);
        if (user.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);
        if (!user.Account.Confirmed) throw new AuthException(ErrorCode.UnconfirmedAccount);

        var code = await _otpRepository.FindByUserIdCodeAndTypeAsync(
            user.Id, dto.ConfirmationCode, OtpType.ResetPassword);
        if (code is null) throw new AuthException(ErrorCode.IncorrectCode);
        if (code.ExpiredAt < DateTime.UtcNow) throw new AuthException(ErrorCode.ExpiredCode);

        var encrypted = _passwordHandler.Encrypt(dto.Password);

        code.Redeemed = true;
        user.PasswordHash = encrypted.Hash;
        user.PasswordSalt = encrypted.Salt;

        await _context.SaveChangesAsync();
    }

    public async Task ModifyPasswordAsync(AuthUser auth, ModifyPasswordDto dto)
    {
        var user = await _userRepository.FindByIdAsync(auth.Id);
        if (user is null) throw new AuthException(ErrorCode.InvalidToken);
        if (user.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);

        var matched = _passwordHandler.Decrypt(dto.CurrentPassword, user.PasswordHash, user.PasswordSalt);
        if (!matched) throw new AuthException(ErrorCode.IncorrectPassword);

        var encrypted = _passwordHandler.Encrypt(dto.Password);
        user.PasswordHash = encrypted.Hash;
        user.PasswordSalt = encrypted.Salt;

        await _context.SaveChangesAsync();
    }

    public async Task ModifyPasswordAsync(ClaimsPrincipal principal, ModifyPasswordDto dto)
    {
        var auth = principal.ToAuthUser();
        await ModifyPasswordAsync(auth, dto);
    }

    public async Task<TokenData> RefreshTokenAsync(TokenData token)
    {
        var userId = _tokenProvider.ExtractUserId(token.AccessToken);

        var user = await _userRepository.FindByIdAsync(userId);
        if (user is null) throw new AuthException(ErrorCode.InvalidToken);
        if (user.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);

        var refreshToken = await _refreshTokenRepository.FindActiveByValue(token.RefreshToken);
        if (refreshToken is null) throw new AuthException(ErrorCode.InvalidToken);
        if (refreshToken.ExpiredAt < DateTime.UtcNow) throw new AuthException(ErrorCode.ExpiredToken);

        var nToken = _tokenProvider.Generate(user);

        refreshToken.Disabled = true;

        user.RefreshTokens.Add(new RefreshToken
        {
            Value = nToken.RefreshToken,
            ExpiredAt = refreshToken.ExpiredAt
        });

        await _context.SaveChangesAsync();

        return nToken;
    }

    public async Task RevokeRefreshTokensAsync(AuthUser auth)
    {
        var user = await _userRepository.FindByIdNoTrackingAsync(auth.Id);
        if (user is null) throw new AuthException(ErrorCode.InvalidToken);
        if (user.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);

        await _refreshTokenRepository.UpdateAsRevokedAsync(auth.Id);
    }

    public async Task RevokeRefreshTokensAsync(ClaimsPrincipal principal)
    {
        var auth = principal.ToAuthUser();
        await RevokeRefreshTokensAsync(auth);
    }

    public async Task ActivateTwoFactorAuthAsync(AuthUser auth)
    {
        var user = await _userRepository.FindByIdAsync(auth.Id);
        if (user is null) throw new AuthException(ErrorCode.InvalidToken);
        if (user.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);
        if (user.TwoFactorAuth is not null && user.TwoFactorAuth.Enabled)
            throw new AuthException(ErrorCode.AlreadyActivatedTwoFactorAuth);

        var key = _keysManager.GenerateSha1Key();

        if (user.TwoFactorAuth is null)
        {
            user.TwoFactorAuth = new TwoFactorAuth { AuthenticatorKey = key };
        }
        else
        {
            user.TwoFactorAuth.AuthenticatorKey = key;
        }

        await _context.SaveChangesAsync();

        var uri = _keysManager.GenerateTotpUri(key, user.Email, _options.Issuer);

        var email = new EmailDto(user.Email,
            "Two Factor Authentication",
            $"<img src= \"https://chart.googleapis.com/chart?chs=250x250&cht=qr&chl={uri}\" />",
            true);

        await _notificationSender.SendEmailAsync(email);
    }

    public async Task ActivateTwoFactorAuthAsync(ClaimsPrincipal principal)
    {
        var auth = principal.ToAuthUser();
        await ActivateTwoFactorAuthAsync(auth);
    }

    public async Task ConfirmTwoFactorAuthActivationAsync(AuthUser auth, ConfirmTwoFactorAuthActivationDto dto)
    {
        var user = await _userRepository.FindByIdAsync(auth.Id);
        if (user is null) throw new AuthException(ErrorCode.InvalidToken);
        if (user.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);
        if (user.TwoFactorAuth is null) throw new AuthException(ErrorCode.EmptyAuthenticatorKey);
        if (user.TwoFactorAuth.Enabled) throw new AuthException(ErrorCode.AlreadyActivatedTwoFactorAuth);

        var matched = _keysManager.ValidateTotpCode(user.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode);
        if (!matched) throw new AuthException(ErrorCode.IncorrectCode);

        user.TwoFactorAuth.Enabled = true;

        await _context.SaveChangesAsync();
    }

    public async Task ConfirmTwoFactorAuthActivationAsync(
        ClaimsPrincipal principal,
        ConfirmTwoFactorAuthActivationDto dto)
    {
        var auth = principal.ToAuthUser();
        await ConfirmTwoFactorAuthActivationAsync(auth, dto);
    }

    public async Task DeactivateTwoFactorAuthAsync(AuthUser auth, DeactivateTwoFactorAuthDto dto)
    {
        var user = await _userRepository.FindByIdAsync(auth.Id);
        if (user is null) throw new AuthException(ErrorCode.InvalidToken);
        if (user.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);
        if (user.TwoFactorAuth is null || !user.TwoFactorAuth.Enabled)
            throw new AuthException(ErrorCode.NotActivatedTwoFactorAuth);

        var matched = _keysManager.ValidateTotpCode(user.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode);
        if (!matched) throw new AuthException(ErrorCode.IncorrectCode);

        user.TwoFactorAuth.Enabled = false;

        await _context.SaveChangesAsync();
    }

    public async Task DeactivateTwoFactorAuthAsync(ClaimsPrincipal principal, DeactivateTwoFactorAuthDto dto)
    {
        var auth = principal.ToAuthUser();
        await DeactivateTwoFactorAuthAsync(auth, dto);
    }
}