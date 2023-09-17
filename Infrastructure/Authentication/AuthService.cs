using System.Security.Claims;
using Application.Authentication;
using Application.Authentication.Data;
using Application.Authentication.Exceptions;
using Application.Keys;
using Application.Notification;
using Application.Notification.Data;
using Application.Password;
using Application.Store;
using Application.Token;
using Application.Token.Data;
using Domain.Data;
using Domain.Entities;
using Domain.Enums;
using Domain.Exceptions;
using Infrastructure.Authentication.Extensions;
using Microsoft.Extensions.Options;

namespace Infrastructure.Authentication;

public class AuthService : IAuthService
{
    private readonly IStore _store;
    private readonly TokenOptions _options;

    private readonly IKeysManager _keysManager;
    private readonly ITokenProvider _tokenProvider;
    private readonly IPasswordHandler _passwordHandler;
    private readonly INotificationSender _notificationSender;

    public AuthService(
        IStore store,
        IOptions<TokenOptions> options,
        IKeysManager keysManager,
        ITokenProvider tokenProvider,
        IPasswordHandler passwordHandler,
        INotificationSender notificationSender)
    {
        _store = store;
        _options = options.Value;
        _keysManager = keysManager;
        _tokenProvider = tokenProvider;
        _passwordHandler = passwordHandler;
        _notificationSender = notificationSender;
    }

    public async Task SignUpAsync(SignUpDto dto)
    {
        var exists = await _store.Users.ExistsByUsernameOrEmailAsync(dto.Username, dto.Email);
        if (exists) throw new AuthException(ErrorCode.InvalidUsernameOrEmail);

        var code = _keysManager.GenerateTotpCode();
        var encrypted = _passwordHandler.Encrypt(dto.Password);

        await _store.Users.SaveAsync(new User
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
                    Code = code.Content,
                    Type = OtpType.RegisterAccount,
                    ExpiredAt = code.IssuedAt.AddMinutes(5)
                }
            }
        });

        await _store.FlushAsync();

        var email = new EmailDto(dto.Email, "Email Confirmation", code.Content);
        await _notificationSender.SendEmailAsync(email);
    }

    public async Task ConfirmSignUpAsync(ConfirmSignUpDto dto)
    {
        User user;
        try
        {
            user = await _store.Users.FindByEmailAsync(dto.Email);
        }
        catch (EntityNotFoundException<User>)
        {
            throw new AuthException(ErrorCode.IncorrectEmail);
        }

        if (user.Account.Confirmed) throw new AuthException(ErrorCode.AlreadyConfirmedAccount);

        Otp code;
        try
        {
            code = await _store.Otp.FindByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode,
                OtpType.RegisterAccount);
        }
        catch (EntityNotFoundException<Otp>)
        {
            throw new AuthException(ErrorCode.IncorrectCode);
        }

        if (code.ExpiredAt < DateTime.UtcNow) throw new AuthException(ErrorCode.ExpiredCode);

        code.Redeemed = true;
        user.EmailConfirmed = true;
        user.Account.Confirmed = true;

        await _store.FlushAsync();
    }

    public async Task ResendSignUpCodeAsync(ResendSignUpCodeDto dto)
    {
        User user;
        try
        {
            user = await _store.Users.FindByEmailAsync(dto.Email);
        }
        catch (EntityNotFoundException<User>)
        {
            throw new AuthException(ErrorCode.IncorrectEmail);
        }

        if (user.Account.Confirmed) throw new AuthException(ErrorCode.AlreadyConfirmedAccount);

        await _store.Otp.UpdateAsDisabledActiveCodesAsync(user.Id, OtpType.RegisterAccount);

        var code = _keysManager.GenerateTotpCode();

        user.OneTimePasswords.Add(new Otp
        {
            Code = code.Content,
            Type = OtpType.RegisterAccount,
            ExpiredAt = code.IssuedAt.AddMinutes(5)
        });

        await _store.FlushAsync();

        var email = new EmailDto(dto.Email, "Email Confirmation", code.Content);
        await _notificationSender.SendEmailAsync(email);
    }

    public async Task<SignInResult> SignInAsync(SignInDto dto)
    {
        User user;
        try
        {
            user = await _store.Users.FindByEmailAsync(dto.Email);
        }
        catch (EntityNotFoundException<User>)
        {
            throw new AuthException(ErrorCode.IncorrectEmailOrPassword);
        }

        if (!user.Account.Confirmed) throw new AuthException(ErrorCode.UnconfirmedAccount);
        if (user.Account.Locked && user.Account.LockEndAt > DateTime.UtcNow)
            throw new AuthException(ErrorCode.LockedAccount);

        var matched = _passwordHandler.Decrypt(dto.Password, user.PasswordHash, user.PasswordSalt);

        user.Account.FailedAccessAttempts = matched ? 0 : user.Account.FailedAccessAttempts + 1;
        user.Account.Locked = user.Account.FailedAccessAttempts >= 5;
        user.Account.LockEndAt = user.Account.Locked ? DateTime.UtcNow.AddMinutes(5) : null;

        if (!matched)
        {
            await _store.FlushAsync();
            throw new AuthException(ErrorCode.IncorrectEmailOrPassword);
        }

        if (user.TwoFactorAuth is { Enabled: true })
        {
            var key = _keysManager.GenerateRandomBase32Key();

            user.TwoFactorAuth.Challenges.Add(new Challenge
            {
                Key = key,
                ExpiredAt = DateTime.UtcNow.AddMinutes(2)
            });

            await _store.FlushAsync();

            return new SignInResult(ChallengeKey: key, SignedIn: false);
        }

        var token = _tokenProvider.CreateToken(user);

        user.RefreshTokens.Add(new RefreshToken
        {
            Value = token.RefreshToken,
            ExpiredAt = DateTime.UtcNow.AddDays(_options.RefreshExpirationInDays)
        });

        await _store.FlushAsync();

        return new SignInResult(token);
    }

    public async Task<SignInResult> TwoFactorSignAsync(TwoFactorSignInDto dto)
    {
        Challenge challenge;
        try
        {
            challenge = await _store.Challenges.FindByKeyAsync(dto.ChallengeKey);
        }
        catch (EntityNotFoundException<Challenge>)
        {
            throw new AuthException(ErrorCode.IncorrectKey);
        }

        if (challenge.ExpiredAt < DateTime.UtcNow) throw new AuthException(ErrorCode.ExpiredKey);
        if (challenge.TwoFactorAuth.User.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);

        var matched = _keysManager.ValidateTotpCode(challenge.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode);
        if (!matched) throw new AuthException(ErrorCode.IncorrectCode);

        challenge.Redeemed = true;

        var token = _tokenProvider.CreateToken(challenge.TwoFactorAuth.User);

        challenge.TwoFactorAuth.User.RefreshTokens.Add(new RefreshToken
        {
            Value = token.RefreshToken,
            ExpiredAt = DateTime.UtcNow.AddDays(_options.RefreshExpirationInDays)
        });

        await _store.FlushAsync();

        return new SignInResult(token);
    }

    public async Task ResetPasswordAsync(ResetPasswordDto dto)
    {
        User user;
        try
        {
            user = await _store.Users.FindByEmailAsync(dto.Email);
        }
        catch (EntityNotFoundException<User>)
        {
            throw new AuthException(ErrorCode.IncorrectEmail);
        }

        if (user.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);
        if (!user.Account.Confirmed) throw new AuthException(ErrorCode.UnconfirmedAccount);

        await _store.Otp.UpdateAsDisabledActiveCodesAsync(user.Id, OtpType.ResetPassword);

        var code = _keysManager.GenerateTotpCode();

        user.OneTimePasswords.Add(new Otp
        {
            Code = code.Content,
            Type = OtpType.ResetPassword,
            ExpiredAt = code.IssuedAt.AddMinutes(5)
        });

        await _store.FlushAsync();

        var email = new EmailDto(dto.Email, "Email Confirmation", code.Content);
        await _notificationSender.SendEmailAsync(email);
    }

    public async Task ConfirmResetPasswordAsync(ConfirmResetPasswordDto dto)
    {
        User user;
        try
        {
            user = await _store.Users.FindByEmailAsync(dto.Email);
        }
        catch (EntityNotFoundException<User>)
        {
            throw new AuthException(ErrorCode.IncorrectEmail);
        }

        if (user.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);
        if (!user.Account.Confirmed) throw new AuthException(ErrorCode.UnconfirmedAccount);

        Otp code;
        try
        {
            code = await _store.Otp.FindByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.ResetPassword);
        }
        catch (EntityNotFoundException<Otp>)
        {
            throw new AuthException(ErrorCode.IncorrectCode);
        }

        if (code.ExpiredAt < DateTime.UtcNow) throw new AuthException(ErrorCode.ExpiredCode);

        var encrypted = _passwordHandler.Encrypt(dto.Password);

        code.Redeemed = true;
        user.PasswordHash = encrypted.Hash;
        user.PasswordSalt = encrypted.Salt;

        await _store.FlushAsync();
    }

    public async Task ModifyPasswordAsync(AuthUser auth, ModifyPasswordDto dto)
    {
        User user;
        try
        {
            user = await _store.Users.FindByIdAsync(auth.Id);
        }
        catch (EntityNotFoundException<User>)
        {
            throw new AuthException(ErrorCode.InvalidToken);
        }

        if (user.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);

        var matched = _passwordHandler.Decrypt(dto.CurrentPassword, user.PasswordHash, user.PasswordSalt);
        if (!matched) throw new AuthException(ErrorCode.IncorrectPassword);

        var encrypted = _passwordHandler.Encrypt(dto.Password);
        user.PasswordHash = encrypted.Hash;
        user.PasswordSalt = encrypted.Salt;

        await _store.FlushAsync();
    }

    public async Task ModifyPasswordAsync(ClaimsPrincipal principal, ModifyPasswordDto dto)
    {
        var auth = principal.ToAuthUser();
        await ModifyPasswordAsync(auth, dto);
    }

    public async Task<TokenData> RefreshTokenAsync(TokenData token)
    {
        var details = _tokenProvider.ReadAccessToken(token.AccessToken);
        var userId = Guid.Parse(details.Subject);

        User user;
        try
        {
            user = await _store.Users.FindByIdAsync(userId);
        }
        catch (EntityNotFoundException<User>)
        {
            throw new AuthException(ErrorCode.InvalidToken);
        }

        if (user.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);

        RefreshToken rt;
        try
        {
            rt = await _store.RefreshTokens.FindActiveByValueAsync(token.RefreshToken);
        }
        catch (EntityNotFoundException<RefreshToken>)
        {
            throw new AuthException(ErrorCode.InvalidToken);
        }

        if (rt.ExpiredAt < DateTime.UtcNow) throw new AuthException(ErrorCode.ExpiredToken);

        var nToken = _tokenProvider.CreateToken(user);

        rt.Disabled = true;

        user.RefreshTokens.Add(new RefreshToken
        {
            Value = nToken.RefreshToken,
            ExpiredAt = rt.ExpiredAt
        });

        await _store.FlushAsync();

        return nToken;
    }

    public async Task RevokeRefreshTokensAsync(AuthUser auth)
    {
        User user;
        try
        {
            user = await _store.Users.FindByIdNoTrackingAsync(auth.Id);
        }
        catch (EntityNotFoundException<User>)
        {
            throw new AuthException(ErrorCode.InvalidToken);
        }

        if (user.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);

        await _store.RefreshTokens.UpdateAsRevokedAsync(auth.Id);
    }

    public async Task RevokeRefreshTokensAsync(ClaimsPrincipal principal)
    {
        var auth = principal.ToAuthUser();
        await RevokeRefreshTokensAsync(auth);
    }

    public async Task ActivateTwoFactorAuthAsync(AuthUser auth)
    {
        User user;
        try
        {
            user = await _store.Users.FindByIdAsync(auth.Id);
        }
        catch (EntityNotFoundException<User>)
        {
            throw new AuthException(ErrorCode.InvalidToken);
        }

        if (user.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);
        if (user.TwoFactorAuth is not null && user.TwoFactorAuth.Enabled)
            throw new AuthException(ErrorCode.AlreadyActivatedTwoFactorAuth);

        var key = _keysManager.GenerateRandomBase32Key();

        if (user.TwoFactorAuth is null)
        {
            user.TwoFactorAuth = new TwoFactorAuth { AuthenticatorKey = key };
        }
        else
        {
            user.TwoFactorAuth.AuthenticatorKey = key;
        }

        await _store.FlushAsync();

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
        User user;
        try
        {
            user = await _store.Users.FindByIdAsync(auth.Id);
        }
        catch (EntityNotFoundException<User>)
        {
            throw new AuthException(ErrorCode.InvalidToken);
        }

        if (user.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);
        if (user.TwoFactorAuth is null) throw new AuthException(ErrorCode.EmptyAuthenticatorKey);
        if (user.TwoFactorAuth.Enabled) throw new AuthException(ErrorCode.AlreadyActivatedTwoFactorAuth);

        var matched = _keysManager.ValidateTotpCode(user.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode);
        if (!matched) throw new AuthException(ErrorCode.IncorrectCode);

        user.TwoFactorAuth.Enabled = true;

        await _store.FlushAsync();
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
        User user;
        try
        {
            user = await _store.Users.FindByIdAsync(auth.Id);
        }
        catch (EntityNotFoundException<User>)
        {
            throw new AuthException(ErrorCode.InvalidToken);
        }

        if (user.Account.Locked) throw new AuthException(ErrorCode.LockedAccount);
        if (user.TwoFactorAuth is null || !user.TwoFactorAuth.Enabled)
            throw new AuthException(ErrorCode.NotActivatedTwoFactorAuth);

        var matched = _keysManager.ValidateTotpCode(user.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode);
        if (!matched) throw new AuthException(ErrorCode.IncorrectCode);

        user.TwoFactorAuth.Enabled = false;

        await _store.FlushAsync();
    }

    public async Task DeactivateTwoFactorAuthAsync(ClaimsPrincipal principal, DeactivateTwoFactorAuthDto dto)
    {
        var auth = principal.ToAuthUser();
        await DeactivateTwoFactorAuthAsync(auth, dto);
    }
}