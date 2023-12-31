using Application.Authentication.Data;
using Application.Authentication.Exceptions;
using Application.Keys;
using Application.Keys.Data;
using Application.Notification;
using Application.Notification.Data;
using Application.Password;
using Application.Password.Data;
using Application.Store;
using Application.Token;
using Application.Token.Exceptions;
using Domain.Data;
using Domain.Entities;
using Domain.Enums;
using Domain.Exceptions;
using Infrastructure.Authentication;
using Infrastructure.UnitTests.Utils;
using Microsoft.Extensions.Options;
using NSubstitute;
using NSubstitute.ExceptionExtensions;

namespace Infrastructure.UnitTests;

public class AuthServiceTests
{
    private readonly AuthService _service;

    private readonly TestUtil _util;
    private readonly IStore _storeMock = Substitute.For<IStore>();
    private readonly IKeysManager _managerMock = Substitute.For<IKeysManager>();
    private readonly ITokenProvider _providerMock = Substitute.For<ITokenProvider>();
    private readonly IPasswordHandler _handlerMock = Substitute.For<IPasswordHandler>();
    private readonly INotificationSender _senderMock = Substitute.For<INotificationSender>();

    public AuthServiceTests()
    {
        _util = new TestUtil();

        var options = Options.Create(_util.TokenOptions);
        _service = new AuthService(
            _storeMock,
            options,
            _managerMock,
            _providerMock,
            _handlerMock,
            _senderMock);
    }

    [Fact]
    public async Task SignUpAsync_UserAlreadyExists_ThrowsAuthException()
    {
        // Arrange
        var dto = new SignUpDto(_util.Email, _util.Name, _util.Password);

        _storeMock
            .Users
            .ExistsByUsernameOrEmailAsync(dto.Username, dto.Email)
            .Returns(true);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.SignUpAsync(dto));
        Assert.Equal(ErrorCode.InvalidUsernameOrEmail, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .ExistsByUsernameOrEmailAsync(dto.Username, dto.Email);

        await _storeMock
            .DidNotReceive()
            .FlushAsync();
    }

    [Fact]
    public async Task SignUpAsync_ValidInput_SuccessfullyRegistersUser()
    {
        // Arrange
        var dto = new SignUpDto(_util.Email, _util.Name, _util.Password);

        _storeMock
            .Users
            .ExistsByUsernameOrEmailAsync(dto.Username, dto.Email)
            .Returns(false);

        var code = new TotpCode(_util.Otp, DateTime.UtcNow);
        _managerMock
            .GenerateTotpCode()
            .Returns(code);

        var encrypted = new EncryptedPassword(_util.Hash, _util.Salt);
        _handlerMock
            .Encrypt(dto.Password)
            .Returns(encrypted);

        // Act
        await _service.SignUpAsync(dto);

        // Assert
        await _storeMock
            .Users
            .Received(1)
            .ExistsByUsernameOrEmailAsync(dto.Username, dto.Email);

        _managerMock
            .Received(1)
            .GenerateTotpCode();

        _handlerMock
            .Received(1)
            .Encrypt(dto.Password);

        await _storeMock
            .Users
            .Received(1)
            .SaveAsync(Arg.Is<User>(user =>
                user.Username == dto.Username &&
                user.Email == dto.Email &&
                user.PasswordHash == encrypted.Hash &&
                user.PasswordSalt == encrypted.Salt &&
                user.OneTimePasswords.Count == 1 &&
                user.OneTimePasswords.First().Code == code.Content &&
                user.OneTimePasswords.First().Type == OtpType.RegisterAccount &&
                user.OneTimePasswords.First().ExpiredAt == code.IssuedAt.AddMinutes(5))
            );

        await _storeMock
            .Received(1)
            .FlushAsync();

        await _senderMock
            .Received(1)
            .SendEmailAsync(
                Arg.Is<EmailDto>(email =>
                    email.Receiver == dto.Email &&
                    email.Subject == "Email Confirmation" &&
                    email.Content.Contains(code.Content)));
    }

    [Fact]
    public async Task ConfirmSignUpAsync_IncorrectEmail_ThrowsAuthException()
    {
        // Arrange
        var dto = new ConfirmSignUpDto(_util.Email, _util.Otp);

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Throws<EntityNotFoundException<User>>();

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ConfirmSignUpAsync(dto));
        Assert.Equal(ErrorCode.IncorrectEmail, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        await _storeMock
            .DidNotReceive()
            .FlushAsync();
    }

    [Fact]
    public async Task ConfirmSignUpAsync_AlreadyConfirmedAccount_ThrowsAuthException()
    {
        // Arrange
        var dto = new ConfirmSignUpDto(_util.Email, _util.Otp);
        var user = _util.User;
        user.Account.Confirmed = true;

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ConfirmSignUpAsync(dto));
        Assert.Equal(ErrorCode.AlreadyConfirmedAccount, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        await _storeMock
            .DidNotReceive()
            .FlushAsync();
    }

    [Fact]
    public async Task ConfirmSignUpAsync_IncorrectCode_ThrowsAuthException()
    {
        // Arrange
        var dto = new ConfirmSignUpDto(_util.Email, _util.Otp);
        var user = _util.User;
        user.Account.Confirmed = false;

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        _storeMock
            .Otp
            .FindActiveByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.RegisterAccount)
            .Throws<EntityNotFoundException<Otp>>();

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ConfirmSignUpAsync(dto));
        Assert.Equal(ErrorCode.IncorrectCode, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        await _storeMock
            .Otp
            .Received(1)
            .FindActiveByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.RegisterAccount);

        await _storeMock
            .DidNotReceive()
            .FlushAsync();
    }

    [Fact]
    public async Task ConfirmSignUpAsync_ExpiredCode_ThrowsAuthException()
    {
        // Arrange
        var dto = new ConfirmSignUpDto(_util.Email, _util.Otp);
        var user = _util.User;
        user.Account.Confirmed = false;

        var code = new Otp
        {
            UserId = user.Id,
            Code = dto.ConfirmationCode,
            Type = OtpType.RegisterAccount,
            ExpiredAt = DateTime.UtcNow
        };

        _storeMock
            .Users.FindByEmailAsync(dto.Email)
            .Returns(user);

        _storeMock
            .Otp
            .FindActiveByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.RegisterAccount)
            .Returns(code);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ConfirmSignUpAsync(dto));
        Assert.Equal(ErrorCode.ExpiredCode, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        await _storeMock
            .Otp
            .Received(1)
            .FindActiveByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.RegisterAccount);

        await _storeMock
            .DidNotReceive()
            .FlushAsync();
    }

    [Fact]
    public async Task ConfirmSignUpAsync_ValidInput_SuccessfullyConfirmsSignUp()
    {
        // Arrange
        var dto = new ConfirmSignUpDto(_util.Email, _util.Otp);
        var user = _util.User;
        user.Account.Confirmed = false;

        var code = new Otp
        {
            UserId = user.Id,
            Code = dto.ConfirmationCode,
            Type = OtpType.RegisterAccount,
            ExpiredAt = DateTime.UtcNow.AddMinutes(5)
        };

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        _storeMock
            .Otp
            .FindActiveByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.RegisterAccount)
            .Returns(code);

        // Act
        await _service.ConfirmSignUpAsync(dto);

        // Assert
        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        await _storeMock
            .Otp
            .Received(1)
            .FindActiveByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.RegisterAccount);

        Assert.True(user.EmailConfirmed);
        Assert.True(user.Account.Confirmed);
        Assert.True(code.Redeemed);

        await _storeMock
            .Received(1)
            .FlushAsync();
    }

    [Fact]
    public async Task ResendSignUpCodeAsync_IncorrectEmail_ThrowsAuthException()
    {
        // Arrange
        var dto = new ResendSignUpCodeDto(_util.Email);

        _storeMock
            .Users.FindByEmailAsync(dto.Email)
            .Throws<EntityNotFoundException<User>>();

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ResendSignUpCodeAsync(dto));
        Assert.Equal(ErrorCode.IncorrectEmail, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        await _storeMock
            .DidNotReceive()
            .FlushAsync();
    }

    [Fact]
    public async Task ResendSignUpCodeAsync_AlreadyConfirmedAccount_ThrowsAuthException()
    {
        // Arrange
        var dto = new ResendSignUpCodeDto(_util.Email);
        var user = _util.User;
        user.Account.Confirmed = true;

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ResendSignUpCodeAsync(dto));
        Assert.Equal(ErrorCode.AlreadyConfirmedAccount, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        await _storeMock
            .DidNotReceive()
            .FlushAsync();
    }

    [Fact]
    public async Task ResendSignUpCodeAsync_ValidInput_SuccessfullyResendsCodeAndEmail()
    {
        // Arrange
        var dto = new ResendSignUpCodeDto(_util.Email);
        var user = _util.User;
        user.Account.Confirmed = false;

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        _storeMock
            .Otp
            .UpdateAsDisabledActiveCodesAsync(user.Id, OtpType.RegisterAccount)
            .Returns(Task.CompletedTask);

        var code = new TotpCode(_util.Otp, DateTime.UtcNow);
        _managerMock
            .GenerateTotpCode()
            .Returns(code);

        // Act
        await _service.ResendSignUpCodeAsync(dto);

        // Assert
        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        await _storeMock
            .Otp
            .Received(1)
            .UpdateAsDisabledActiveCodesAsync(user.Id, OtpType.RegisterAccount);

        _managerMock
            .Received(1)
            .GenerateTotpCode();

        Assert.Single(user.OneTimePasswords);
        Assert.Equal(code.Content, user.OneTimePasswords.First().Code);
        Assert.Equal(OtpType.RegisterAccount, user.OneTimePasswords.First().Type);
        Assert.Equal(code.IssuedAt.AddMinutes(5), user.OneTimePasswords.First().ExpiredAt);

        await _storeMock
            .Received(1)
            .FlushAsync();

        await _senderMock
            .Received(1)
            .SendEmailAsync(
                Arg.Is<EmailDto>(email =>
                    email.Receiver == dto.Email &&
                    email.Subject == "Email Confirmation" &&
                    email.Content.Contains(code.Content)));
    }

    [Fact]
    public async Task SignInAsync_IncorrectEmail_ThrowsAuthException()
    {
        // Arrange
        var dto = new SignInDto(_util.Email, _util.Password);

        _storeMock
            .Users.FindByEmailAsync(dto.Email)
            .Throws<EntityNotFoundException<User>>();

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.SignInAsync(dto));
        Assert.Equal(ErrorCode.IncorrectEmailOrPassword, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        _handlerMock
            .DidNotReceive()
            .Decrypt(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());

        await _storeMock
            .DidNotReceive()
            .FlushAsync();
    }

    [Fact]
    public async Task SignInAsync_UnconfirmedAccount_ThrowsAuthException()
    {
        // Arrange
        var dto = new SignInDto(_util.Email, _util.Password);
        var user = _util.User;
        user.Account.Confirmed = false;

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.SignInAsync(dto));
        Assert.Equal(ErrorCode.UnconfirmedAccount, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        _handlerMock
            .DidNotReceive()
            .Decrypt(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());

        await _storeMock
            .DidNotReceive()
            .FlushAsync();
    }

    [Fact]
    public async Task SignInAsync_AccountLocked_ThrowsAuthException()
    {
        // Arrange
        var dto = new SignInDto(_util.Email, _util.Password);
        var user = _util.User;
        user.Account.Confirmed = true;
        user.Account.Locked = true;
        user.Account.LockEndAt = DateTime.UtcNow.AddSeconds(1); // account unlocks in 1 second

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.SignInAsync(dto));
        Assert.Equal(ErrorCode.LockedAccount, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        _handlerMock
            .DidNotReceive()
            .Decrypt(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());

        await _storeMock
            .DidNotReceive()
            .FlushAsync();
    }

    [Fact]
    public async Task SignInAsync_IncorrectPassword_IncreaseFailedAttempts_ThrowsAuthException()
    {
        // Arrange
        var dto = new SignInDto(_util.Email, _util.Password);
        var user = _util.User;
        user.Account.Confirmed = true;
        user.Account.Locked = false;
        user.Account.LockEndAt = null;
        user.Account.FailedAccessAttempts = 1; // let's say that user already have one failed sign in attempt

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        _handlerMock
            .Decrypt(dto.Password, user.PasswordHash, user.PasswordSalt)
            .Returns(false);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.SignInAsync(dto));
        Assert.Equal(ErrorCode.IncorrectEmailOrPassword, ex.ErrorCode);

        Assert.False(user.Account.Locked); // user is not locked
        Assert.Null(user.Account.LockEndAt); // user does not have any lock end timestamp set up
        Assert.Equal(2, user.Account.FailedAccessAttempts); // failed sign in attempts increased by one

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        _handlerMock
            .Received(1)
            .Decrypt(dto.Password, user.PasswordHash, user.PasswordSalt);

        await _storeMock
            .Received(1)
            .FlushAsync();
    }

    [Fact]
    public async Task SignInAsync_FiveFailedAttempts_LockAccount_ThrowsAuthException()
    {
        // Arrange
        var dto = new SignInDto(_util.Email, _util.Password);
        var user = _util.User;
        user.Account.Confirmed = true;
        user.Account.Locked = false;
        user.Account.LockEndAt = null;
        user.Account.FailedAccessAttempts = 4; // let's say that user already have four failed sign in attempts

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        _handlerMock
            .Decrypt(dto.Password, user.PasswordHash, user.PasswordSalt)
            .Returns(false);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.SignInAsync(dto));
        Assert.Equal(ErrorCode.IncorrectEmailOrPassword, ex.ErrorCode);

        Assert.True(user.Account.Locked); // user is locked
        Assert.Equal(5, user.Account.FailedAccessAttempts); // failed sign in attempts increased by one

        var lockMinutes = (user.Account.LockEndAt - DateTime.UtcNow)!.Value.Minutes;
        Assert.InRange(lockMinutes, 4, 5); // lock is between 4 to 5 minutes

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        _handlerMock
            .Received(1)
            .Decrypt(dto.Password, user.PasswordHash, user.PasswordSalt);

        await _storeMock
            .Received(1)
            .FlushAsync();
    }

    [Fact]
    public async Task SignInAsync_ValidInput_TwoFactorAuthEnabled_SuccessfullyReturnsChallengeKey()
    {
        // Arrange
        var dto = new SignInDto(_util.Email, _util.Password);
        var user = _util.User;
        user.Account.Confirmed = true; // account is confirmed
        user.TwoFactorAuth!.Enabled = true; // 2fa is enabled
        user.Account.Locked = true; // user was previously locked
        user.Account.LockEndAt = DateTime.UtcNow; // but user lock expired
        user.Account.FailedAccessAttempts = 5;

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        _handlerMock
            .Decrypt(dto.Password, user.PasswordHash, user.PasswordSalt)
            .Returns(true);

        var key = _util.AuthenticatorKey;
        _managerMock
            .GenerateRandomBase32Key()
            .Returns(key);

        // Act
        var result = await _service.SignInAsync(dto);

        // Assert
        Assert.False(user.Account.Locked);
        Assert.Null(user.Account.LockEndAt);
        Assert.Equal(0, user.Account.FailedAccessAttempts);
        Assert.Single(user.TwoFactorAuth.Challenges);
        Assert.Equal(key, user.TwoFactorAuth.Challenges.First().Key);

        var lockMinutes = (user.TwoFactorAuth.Challenges.First().ExpiredAt - DateTime.UtcNow).Minutes;
        Assert.InRange(lockMinutes, 1, 2); // key is valid between 1 to 2 minutes

        Assert.Null(result.Token);
        Assert.False(result.SignedIn);
        Assert.Equal(key, result.ChallengeKey);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        _handlerMock
            .Received(1)
            .Decrypt(dto.Password, user.PasswordHash, user.PasswordSalt);

        _managerMock
            .Received(1)
            .GenerateRandomBase32Key();

        await _storeMock
            .Received(1)
            .FlushAsync();
    }

    [Fact]
    public async Task SignInAsync_ValidInput_SuccessfullySignIn()
    {
        // Arrange
        var dto = new SignInDto(_util.Email, _util.Password);
        var user = _util.User;
        user.Account.Confirmed = true;
        user.TwoFactorAuth!.Enabled = false;
        user.Account.Locked = true;
        user.Account.LockEndAt = null;
        user.Account.FailedAccessAttempts = 0;

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        _handlerMock
            .Decrypt(dto.Password, user.PasswordHash, user.PasswordSalt)
            .Returns(true);

        var token = new TokenData(string.Empty, string.Empty);
        _providerMock
            .CreateToken(user)
            .Returns(token);

        // Act
        var result = await _service.SignInAsync(dto);

        // Assert
        Assert.False(user.Account.Locked);
        Assert.Null(user.Account.LockEndAt);
        Assert.Equal(0, user.Account.FailedAccessAttempts);
        Assert.Empty(user.TwoFactorAuth.Challenges);

        Assert.Equal(token, result.Token);
        Assert.True(result.SignedIn);
        Assert.Null(result.ChallengeKey);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        _handlerMock
            .Received(1)
            .Decrypt(dto.Password, user.PasswordHash, user.PasswordSalt);

        _providerMock
            .Received(1)
            .CreateToken(user);

        await _storeMock
            .Received(1)
            .FlushAsync();
    }

    [Fact]
    public async Task TwoFactorSignInAsync_IncorrectKey_ThrowsAuthException()
    {
        // Arrange
        var dto = new TwoFactorSignInDto(_util.AuthenticatorKey, _util.Otp);

        _storeMock
            .Challenges
            .FindByKeyAsync(dto.ChallengeKey)
            .Throws<EntityNotFoundException<Challenge>>();

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.TwoFactorSignInAsync(dto));
        Assert.Equal(ErrorCode.IncorrectKey, ex.ErrorCode);

        await _storeMock
            .Challenges
            .Received(1)
            .FindByKeyAsync(dto.ChallengeKey);
    }

    [Fact]
    public async Task TwoFactorSignInAsync_RedeemedKey_ThrowsAuthException()
    {
        // Arrange
        var dto = new TwoFactorSignInDto(_util.AuthenticatorKey, _util.Otp);
        var challenge = _util.Challenge;
        challenge.Redeemed = true;

        _storeMock
            .Challenges
            .FindByKeyAsync(dto.ChallengeKey)
            .Returns(challenge);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.TwoFactorSignInAsync(dto));
        Assert.Equal(ErrorCode.IncorrectKey, ex.ErrorCode);

        await _storeMock
            .Challenges
            .Received(1)
            .FindByKeyAsync(dto.ChallengeKey);
    }

    [Fact]
    public async Task TwoFactorSignInAsync_ExpiredKey_ThrowsAuthException()
    {
        // Arrange
        var dto = new TwoFactorSignInDto(_util.AuthenticatorKey, _util.Otp);
        var challenge = _util.Challenge;
        challenge.ExpiredAt = DateTime.UtcNow;

        _storeMock
            .Challenges
            .FindByKeyAsync(dto.ChallengeKey)
            .Returns(challenge);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.TwoFactorSignInAsync(dto));
        Assert.Equal(ErrorCode.ExpiredKey, ex.ErrorCode);

        await _storeMock
            .Challenges
            .Received(1)
            .FindByKeyAsync(dto.ChallengeKey);
    }

    [Fact]
    public async Task TwoFactorSignInAsync_LockedAccount_ThrowsAuthException()
    {
        // Arrange
        var dto = new TwoFactorSignInDto(_util.AuthenticatorKey, _util.Otp);
        var challenge = _util.Challenge;
        challenge.TwoFactorAuth.User.Account.Locked = true;
        challenge.Redeemed = false;
        challenge.ExpiredAt = DateTime.UtcNow.AddMinutes(1);

        _storeMock
            .Challenges
            .FindByKeyAsync(dto.ChallengeKey)
            .Returns(challenge);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.TwoFactorSignInAsync(dto));
        Assert.Equal(ErrorCode.LockedAccount, ex.ErrorCode);

        await _storeMock
            .Challenges
            .Received(1)
            .FindByKeyAsync(dto.ChallengeKey);
    }

    [Fact]
    public async Task TwoFactorSignInAsync_IncorrectCode_ThrowsAuthException()
    {
        // Arrange
        var dto = new TwoFactorSignInDto(_util.AuthenticatorKey, _util.Otp);
        var challenge = _util.Challenge;
        challenge.TwoFactorAuth.User.Account.Locked = false;
        challenge.Redeemed = false;
        challenge.ExpiredAt = DateTime.UtcNow.AddMinutes(1);

        _storeMock
            .Challenges
            .FindByKeyAsync(dto.ChallengeKey)
            .Returns(challenge);

        _managerMock
            .ValidateTotpCode(challenge.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode)
            .Returns(false);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.TwoFactorSignInAsync(dto));
        Assert.Equal(ErrorCode.IncorrectCode, ex.ErrorCode);

        await _storeMock
            .Challenges
            .Received(1)
            .FindByKeyAsync(dto.ChallengeKey);

        _managerMock
            .Received(1)
            .ValidateTotpCode(challenge.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode);
    }

    [Fact]
    public async Task TwoFactorSignInAsync_ValidInput_SuccessfullySignIn()
    {
        // Arrange
        var dto = new TwoFactorSignInDto(_util.AuthenticatorKey, _util.Otp);
        var challenge = _util.Challenge;
        challenge.TwoFactorAuth.User.Account.Locked = false;
        challenge.Redeemed = false;
        challenge.ExpiredAt = DateTime.UtcNow.AddMinutes(1);
        var expirationInDays = _util.TokenOptions.RefreshExpirationInDays;

        _storeMock
            .Challenges
            .FindByKeyAsync(dto.ChallengeKey)
            .Returns(challenge);

        _managerMock
            .ValidateTotpCode(challenge.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode)
            .Returns(true);

        var token = new TokenData(string.Empty, string.Empty);
        _providerMock
            .CreateToken(challenge.TwoFactorAuth.User)
            .Returns(token);

        // Act
        var result = await _service.TwoFactorSignInAsync(dto);

        // Assert
        Assert.True(result.SignedIn);
        Assert.True(challenge.Redeemed);
        Assert.Single(challenge.TwoFactorAuth.User.RefreshTokens);

        var refreshToken = challenge.TwoFactorAuth.User.RefreshTokens.First();
        Assert.Equal(token.RefreshToken, refreshToken.Value);
        Assert.Equal(token.RefreshToken, result.Token!.RefreshToken);
        Assert.Equal(token.AccessToken, result.Token!.AccessToken);

        var validDays = (refreshToken.ExpiredAt - DateTime.UtcNow).Days;
        Assert.InRange(validDays, expirationInDays - 1, expirationInDays);

        await _storeMock
            .Challenges
            .Received(1)
            .FindByKeyAsync(dto.ChallengeKey);

        _managerMock
            .Received(1)
            .ValidateTotpCode(challenge.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode);

        _providerMock
            .Received(1)
            .CreateToken(challenge.TwoFactorAuth.User);

        await _storeMock
            .Received(1)
            .FlushAsync();
    }

    [Fact]
    public async Task ResetPasswordAsync_IncorrectEmail_ThrowsAuthException()
    {
        // Arrange
        var dto = new ResetPasswordDto(_util.Email);

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Throws<EntityNotFoundException<User>>();

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ResetPasswordAsync(dto));
        Assert.Equal(ErrorCode.IncorrectEmail, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        await _storeMock
            .DidNotReceive()
            .FlushAsync();
    }

    [Fact]
    public async Task ResetPasswordAsync_LockedAccount_ThrowsAuthException()
    {
        // Arrange
        var dto = new ResetPasswordDto(_util.Email);
        var user = _util.User;
        user.Account.Locked = true;

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ResetPasswordAsync(dto));
        Assert.Equal(ErrorCode.LockedAccount, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        await _storeMock
            .DidNotReceive()
            .FlushAsync();
    }

    [Fact]
    public async Task ResetPasswordAsync_UnconfirmedAccount_ThrowsAuthException()
    {
        // Arrange
        var dto = new ResetPasswordDto(_util.Email);
        var user = _util.User;
        user.Account.Locked = false;
        user.Account.Confirmed = false;

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ResetPasswordAsync(dto));
        Assert.Equal(ErrorCode.UnconfirmedAccount, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        await _storeMock
            .DidNotReceive()
            .FlushAsync();
    }

    [Fact]
    public async Task ResetPasswordAsync_ValidInput_SuccessfullyResetPassword()
    {
        // Arrange
        var dto = new ResetPasswordDto(_util.Email);
        var user = _util.User;
        user.Account.Locked = false;
        user.Account.Confirmed = true;

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        _storeMock
            .Otp
            .UpdateAsDisabledActiveCodesAsync(user.Id, OtpType.ResetPassword)
            .Returns(Task.CompletedTask);

        var code = new TotpCode(_util.Otp, DateTime.UtcNow);
        _managerMock
            .GenerateTotpCode()
            .Returns(code);

        // Act
        await _service.ResetPasswordAsync(dto);

        // Assert
        Assert.Single(user.OneTimePasswords);
        Assert.Equal(code.Content, user.OneTimePasswords.First().Code);
        Assert.Equal(OtpType.ResetPassword, user.OneTimePasswords.First().Type);
        Assert.Equal(code.IssuedAt.AddMinutes(5), user.OneTimePasswords.First().ExpiredAt);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        await _storeMock
            .Otp
            .Received(1)
            .UpdateAsDisabledActiveCodesAsync(user.Id, OtpType.ResetPassword);

        _managerMock
            .Received(1)
            .GenerateTotpCode();

        await _storeMock
            .Received(1)
            .FlushAsync();

        await _senderMock
            .Received(1)
            .SendEmailAsync(
                Arg.Is<EmailDto>(email =>
                    email.Receiver == dto.Email &&
                    email.Subject == "Email Confirmation" &&
                    email.Content.Contains(code.Content)));
    }

    [Fact]
    public async Task ConfirmResetPasswordAsync_IncorrectEmail_ThrowsAuthException()
    {
        // Arrange
        var dto = new ConfirmResetPasswordDto(_util.Email, _util.Password, _util.Otp);

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Throws<EntityNotFoundException<User>>();

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ConfirmResetPasswordAsync(dto));
        Assert.Equal(ErrorCode.IncorrectEmail, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);
    }

    [Fact]
    public async Task ConfirmResetPasswordAsync_LockedAccount_ThrowsAuthException()
    {
        // Arrange
        var dto = new ConfirmResetPasswordDto(_util.Email, _util.Password, _util.Otp);
        var user = _util.User;
        user.Account.Locked = true;

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ConfirmResetPasswordAsync(dto));
        Assert.Equal(ErrorCode.LockedAccount, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);
    }

    [Fact]
    public async Task ConfirmResetPasswordAsync_UnconfirmedAccount_ThrowsAuthException()
    {
        // Arrange
        var dto = new ConfirmResetPasswordDto(_util.Email, _util.Password, _util.Otp);
        var user = _util.User;
        user.Account.Locked = false;
        user.Account.Confirmed = false;

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ConfirmResetPasswordAsync(dto));
        Assert.Equal(ErrorCode.UnconfirmedAccount, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);
    }

    [Fact]
    public async Task ConfirmResetPasswordAsync_IncorrectCode_ThrowsAuthException()
    {
        // Arrange
        var dto = new ConfirmResetPasswordDto(_util.Email, _util.Password, _util.Otp);
        var user = _util.User;
        user.Account.Locked = false;
        user.Account.Confirmed = true;

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        _storeMock
            .Otp
            .FindActiveByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.ResetPassword)
            .Throws<EntityNotFoundException<Otp>>();

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ConfirmResetPasswordAsync(dto));
        Assert.Equal(ErrorCode.IncorrectCode, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        await _storeMock
            .Otp
            .Received(1)
            .FindActiveByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.ResetPassword);
    }

    [Fact]
    public async Task ConfirmResetPasswordAsync_ExpiredCode_ThrowsAuthException()
    {
        // Arrange
        var dto = new ConfirmResetPasswordDto(_util.Email, _util.Password, _util.Otp);
        var user = _util.User;
        user.Account.Locked = false;
        user.Account.Confirmed = true;

        var code = new Otp
        {
            UserId = user.Id,
            Code = dto.ConfirmationCode,
            Type = OtpType.RegisterAccount,
            ExpiredAt = DateTime.UtcNow // expired
        };

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        _storeMock
            .Otp
            .FindActiveByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.ResetPassword)
            .Returns(code);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ConfirmResetPasswordAsync(dto));
        Assert.Equal(ErrorCode.ExpiredCode, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        await _storeMock
            .Otp
            .Received(1)
            .FindActiveByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.ResetPassword);
    }

    [Fact]
    public async Task ConfirmResetPasswordAsync_ValidInput_SuccessfullyConfirmResetPassword()
    {
        // Arrange
        var dto = new ConfirmResetPasswordDto(_util.Email, _util.Password, _util.Otp);
        var user = _util.User;
        user.Account.Locked = false;
        user.Account.Confirmed = true;

        var code = new Otp
        {
            UserId = user.Id,
            Code = dto.ConfirmationCode,
            Type = OtpType.RegisterAccount,
            ExpiredAt = DateTime.UtcNow.AddSeconds(2) // not expired yet
        };

        _storeMock
            .Users
            .FindByEmailAsync(dto.Email)
            .Returns(user);

        _storeMock
            .Otp
            .FindActiveByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.ResetPassword)
            .Returns(code);

        var encrypted = new EncryptedPassword(string.Empty, string.Empty);
        _handlerMock
            .Encrypt(dto.Password)
            .Returns(encrypted);

        // Act
        await _service.ConfirmResetPasswordAsync(dto);

        // Assert
        Assert.True(code.Redeemed);
        Assert.Equal(encrypted.Hash, user.PasswordHash);
        Assert.Equal(encrypted.Salt, user.PasswordSalt);

        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        await _storeMock
            .Otp
            .Received(1)
            .FindActiveByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.ResetPassword);

        _handlerMock
            .Received(1)
            .Encrypt(dto.Password);

        await _storeMock
            .Received(1)
            .FlushAsync();
    }

    [Fact]
    public async Task ModifyPasswordAsync_InvalidToken_ThrowsAuthException()
    {
        // Arrange
        var dto = new ModifyPasswordDto(string.Empty, _util.Password);
        var auth = _util.AuthUser;

        _storeMock
            .Users
            .FindByIdAsync(auth.Id)
            .Throws<EntityNotFoundException<User>>();

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ModifyPasswordAsync(auth, dto));
        Assert.Equal(ErrorCode.InvalidToken, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(auth.Id);
    }

    [Fact]
    public async Task ModifyPasswordAsync_LockedAccount_ThrowsAuthException()
    {
        // Arrange
        var dto = new ModifyPasswordDto(string.Empty, _util.Password);
        var auth = _util.AuthUser;
        var user = _util.User;
        user.Account.Locked = true;

        _storeMock
            .Users
            .FindByIdAsync(user.Id)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ModifyPasswordAsync(auth, dto));
        Assert.Equal(ErrorCode.LockedAccount, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(user.Id);
    }

    [Fact]
    public async Task ModifyPasswordAsync_IncorrectPassword_ThrowsAuthException()
    {
        // Arrange
        var dto = new ModifyPasswordDto(_util.Password, "comeIn123@@");
        var auth = _util.AuthUser;
        var user = _util.User;
        user.Account.Locked = false;

        _storeMock
            .Users
            .FindByIdAsync(user.Id)
            .Returns(user);

        _handlerMock
            .Decrypt(dto.CurrentPassword, user.PasswordHash, user.PasswordSalt)
            .Returns(false);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ModifyPasswordAsync(auth, dto));
        Assert.Equal(ErrorCode.IncorrectPassword, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(user.Id);

        _handlerMock
            .Received(1)
            .Decrypt(dto.CurrentPassword, user.PasswordHash, user.PasswordSalt);
    }

    [Fact]
    public async Task ModifyPasswordAsync_ValidInput_SuccessfullyModifyPassword()
    {
        // Arrange
        var dto = new ModifyPasswordDto(_util.Password, "comeIn123@@");
        var auth = _util.AuthUser;
        var user = _util.User;
        user.Account.Locked = false;
        var encrypted = new EncryptedPassword(string.Empty, string.Empty);

        _storeMock
            .Users
            .FindByIdAsync(user.Id)
            .Returns(user);

        _handlerMock
            .Decrypt(dto.CurrentPassword, user.PasswordHash, user.PasswordSalt)
            .Returns(true);

        _handlerMock
            .Encrypt(dto.Password)
            .Returns(encrypted);

        // Act
        await _service.ModifyPasswordAsync(auth, dto);

        // Assert
        Assert.Equal(encrypted.Hash, user.PasswordHash);
        Assert.Equal(encrypted.Salt, user.PasswordSalt);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(user.Id);

        _handlerMock
            .ReceivedWithAnyArgs(1)
            .Decrypt(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>());

        _handlerMock
            .Received(1)
            .Encrypt(dto.Password);

        await _storeMock
            .Received(1)
            .FlushAsync();
    }

    [Fact]
    public async Task RefreshTokenAsync_InvalidToken_ThrowsAuthException()
    {
        // Arrange
        var token = new TokenData(string.Empty, string.Empty);

        _providerMock
            .ReadAccessToken(token.AccessToken)
            .Throws(new InvalidTokenException(token.AccessToken));

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.RefreshTokenAsync(token));
        Assert.Equal(ErrorCode.InvalidToken, ex.ErrorCode);

        _providerMock
            .Received(1)
            .ReadAccessToken(token.AccessToken);
    }

    [Fact]
    public async Task RefreshTokenAsync_InvalidTokenUser_ThrowsAuthException()
    {
        // Arrange
        var token = new TokenData(string.Empty, string.Empty);
        var details = _util.TokenDetails;
        var userId = new Guid(details.Subject);

        _providerMock
            .ReadAccessToken(token.AccessToken)
            .Returns(details);

        _storeMock
            .Users
            .FindByIdAsync(userId)
            .Throws<EntityNotFoundException<User>>();

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.RefreshTokenAsync(token));
        Assert.Equal(ErrorCode.InvalidToken, ex.ErrorCode);

        _providerMock
            .Received(1)
            .ReadAccessToken(token.AccessToken);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(userId);
    }

    [Fact]
    public async Task RefreshTokenAsync_LockedAccount_ThrowsAuthException()
    {
        // Arrange
        var token = new TokenData(string.Empty, string.Empty);
        var details = _util.TokenDetails;
        var user = _util.User;
        user.Account.Locked = true;

        _providerMock
            .ReadAccessToken(token.AccessToken)
            .Returns(details);

        _storeMock
            .Users
            .FindByIdAsync(user.Id)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.RefreshTokenAsync(token));
        Assert.Equal(ErrorCode.LockedAccount, ex.ErrorCode);

        _providerMock
            .Received(1)
            .ReadAccessToken(token.AccessToken);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(user.Id);
    }

    [Fact]
    public async Task RefreshTokenAsync_InvalidRefreshToken_ThrowsAuthException()
    {
        // Arrange
        var token = new TokenData(string.Empty, string.Empty);
        var details = _util.TokenDetails;
        var user = _util.User;
        user.Account.Locked = false;

        _providerMock
            .ReadAccessToken(token.AccessToken)
            .Returns(details);

        _storeMock
            .Users
            .FindByIdAsync(user.Id)
            .Returns(user);

        _storeMock
            .RefreshTokens
            .FindActiveByValueAsync(token.RefreshToken)
            .Throws<EntityNotFoundException<RefreshToken>>();

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.RefreshTokenAsync(token));
        Assert.Equal(ErrorCode.InvalidToken, ex.ErrorCode);

        _providerMock
            .Received(1)
            .ReadAccessToken(token.AccessToken);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(user.Id);

        await _storeMock
            .RefreshTokens
            .Received(1)
            .FindActiveByValueAsync(token.RefreshToken);
    }

    [Fact]
    public async Task RefreshTokenAsync_ExpiredToken_ThrowsAuthException()
    {
        // Arrange
        var token = new TokenData(string.Empty, string.Empty);
        var details = _util.TokenDetails;
        var user = _util.User;
        user.Account.Locked = false;

        var refresh = new RefreshToken
        {
            Value = token.RefreshToken,
            ExpiredAt = DateTime.UtcNow // expired
        };

        _providerMock
            .ReadAccessToken(token.AccessToken)
            .Returns(details);

        _storeMock
            .Users
            .FindByIdAsync(user.Id)
            .Returns(user);

        _storeMock
            .RefreshTokens
            .FindActiveByValueAsync(token.RefreshToken)
            .Returns(refresh);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.RefreshTokenAsync(token));
        Assert.Equal(ErrorCode.ExpiredToken, ex.ErrorCode);

        _providerMock
            .Received(1)
            .ReadAccessToken(token.AccessToken);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(user.Id);

        await _storeMock
            .RefreshTokens
            .Received(1)
            .FindActiveByValueAsync(token.RefreshToken);
    }

    [Fact]
    public async Task RefreshTokenAsync_ValidInput_SuccessfullyRefreshToken()
    {
        // Arrange
        var token = new TokenData(string.Empty, string.Empty);
        var details = _util.TokenDetails;
        var user = _util.User;
        user.Account.Locked = false;

        var refresh = new RefreshToken
        {
            Disabled = false,
            Value = token.RefreshToken,
            ExpiredAt = DateTime.UtcNow.AddMinutes(2) // not expired
        };

        _providerMock
            .ReadAccessToken(token.AccessToken)
            .Returns(details);

        _storeMock
            .Users
            .FindByIdAsync(user.Id)
            .Returns(user);

        _storeMock
            .RefreshTokens
            .FindActiveByValueAsync(token.RefreshToken)
            .Returns(refresh);

        var nToken = new TokenData(string.Empty, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
        _providerMock
            .CreateToken(user)
            .Returns(nToken);

        // Act
        await _service.RefreshTokenAsync(token);

        Assert.True(refresh.Disabled);
        Assert.Single(user.RefreshTokens);
        Assert.Equal(nToken.RefreshToken, user.RefreshTokens.First().Value);
        // new refresh token is created but it keeps the previous valid time
        Assert.Equal(refresh.ExpiredAt, user.RefreshTokens.First().ExpiredAt);

        // Assert
        _providerMock
            .Received(1)
            .ReadAccessToken(token.AccessToken);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(user.Id);

        await _storeMock
            .RefreshTokens
            .Received(1)
            .FindActiveByValueAsync(token.RefreshToken);

        _providerMock
            .Received(1)
            .CreateToken(user);

        await _storeMock
            .Received(1)
            .FlushAsync();
    }

    [Fact]
    public async Task RevokeRefreshTokensAsync_InvalidToken_ThrowsAuthException()
    {
        // Arrange
        var auth = _util.AuthUser;

        _storeMock
            .Users
            .FindByIdNoTrackingAsync(auth.Id)
            .Throws<EntityNotFoundException<User>>();

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.RevokeRefreshTokensAsync(auth));
        Assert.Equal(ErrorCode.InvalidToken, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdNoTrackingAsync(auth.Id);
    }

    [Fact]
    public async Task RevokeRefreshTokensAsync_LockedAccount_ThrowsAuthException()
    {
        // Arrange
        var auth = _util.AuthUser;
        var user = _util.User;
        user.Account.Locked = true;

        _storeMock
            .Users
            .FindByIdNoTrackingAsync(auth.Id)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.RevokeRefreshTokensAsync(auth));
        Assert.Equal(ErrorCode.LockedAccount, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdNoTrackingAsync(auth.Id);
    }

    [Fact]
    public async Task RevokeRefreshTokensAsync_ValidInput_SuccessfullyRevokeRefreshTokens()
    {
        // Arrange
        var auth = _util.AuthUser;
        var user = _util.User;
        user.Account.Locked = false;

        _storeMock
            .Users
            .FindByIdNoTrackingAsync(auth.Id)
            .Returns(user);

        _storeMock
            .RefreshTokens
            .UpdateAsRevokedAsync(auth.Id)
            .Returns(Task.CompletedTask);

        // Act
        await _service.RevokeRefreshTokensAsync(auth);

        // Assert
        await _storeMock
            .Users
            .Received(1)
            .FindByIdNoTrackingAsync(auth.Id);

        await _storeMock
            .RefreshTokens
            .Received(1)
            .UpdateAsRevokedAsync(auth.Id);
    }

    [Fact]
    public async Task ActivateTwoFactorAuthAsync_InvalidToken_ThrowsAuthException()
    {
        // Arrange
        var auth = _util.AuthUser;

        _storeMock
            .Users
            .FindByIdAsync(auth.Id)
            .Throws<EntityNotFoundException<User>>();

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ActivateTwoFactorAuthAsync(auth));
        Assert.Equal(ErrorCode.InvalidToken, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(auth.Id);
    }

    [Fact]
    public async Task ActivateTwoFactorAuthAsync_LockedAccount_ThrowsAuthException()
    {
        // Arrange
        var auth = _util.AuthUser;
        var user = _util.User;
        user.Account.Locked = true;

        _storeMock
            .Users
            .FindByIdAsync(auth.Id)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ActivateTwoFactorAuthAsync(auth));
        Assert.Equal(ErrorCode.LockedAccount, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(auth.Id);
    }

    [Fact]
    public async Task ActivateTwoFactorAuthAsync_AlreadyActivated_ThrowsAuthException()
    {
        // Arrange
        var auth = _util.AuthUser;
        var user = _util.User;
        user.Account.Locked = false;
        user.TwoFactorAuth!.Enabled = true;

        _storeMock
            .Users
            .FindByIdAsync(auth.Id)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ActivateTwoFactorAuthAsync(auth));
        Assert.Equal(ErrorCode.AlreadyActivatedTwoFactorAuth, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(auth.Id);
    }

    [Fact]
    public async Task ActivateTwoFactorAuthAsync_ValidInput_SuccessfullyActivateTwoFactorAuth()
    {
        // Arrange
        var auth = _util.AuthUser;
        var user = _util.User;
        user.Account.Locked = false;
        user.TwoFactorAuth = null;
        var key = _util.AuthenticatorKey;
        var options = _util.TokenOptions;
        const string uri = "mock_uri";

        _storeMock
            .Users
            .FindByIdAsync(auth.Id)
            .Returns(user);

        _managerMock
            .GenerateRandomBase32Key()
            .Returns(key);

        _managerMock
            .GenerateTotpUri(key, user.Email, options.Issuer)
            .Returns(uri);

        // Act
        await _service.ActivateTwoFactorAuthAsync(auth);

        // Assert
        Assert.NotNull(user.TwoFactorAuth);
        Assert.Equal(key, user.TwoFactorAuth.AuthenticatorKey);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(auth.Id);

        _managerMock
            .Received(1)
            .GenerateRandomBase32Key();

        await _storeMock
            .Received(1)
            .FlushAsync();

        _managerMock
            .Received(1)
            .GenerateTotpUri(key, user.Email, options.Issuer);

        await _senderMock
            .Received(1)
            .SendEmailAsync(
                Arg.Is<EmailDto>(email =>
                    email.Receiver == user.Email &&
                    email.Subject == "Two Factor Authentication" &&
                    email.Content ==
                    $"<img src= \"https://chart.googleapis.com/chart?chs=250x250&cht=qr&chl={uri}\" />" &&
                    email.Html)
            );
    }

    [Fact]
    public async Task ConfirmTwoFactorAuthActivationAsync_InvalidToken_ThrowsAuthException()
    {
        // Arrange
        var auth = _util.AuthUser;
        var dto = new ConfirmTwoFactorAuthActivationDto(_util.Otp);

        _storeMock
            .Users
            .FindByIdAsync(auth.Id)
            .Throws<EntityNotFoundException<User>>();

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () =>
            await _service.ConfirmTwoFactorAuthActivationAsync(auth, dto));
        Assert.Equal(ErrorCode.InvalidToken, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(auth.Id);
    }

    [Fact]
    public async Task ConfirmTwoFactorAuthActivationAsync_LockedAccount_ThrowsAuthException()
    {
        // Arrange
        var auth = _util.AuthUser;
        var dto = new ConfirmTwoFactorAuthActivationDto(_util.Otp);
        var user = _util.User;
        user.Account.Locked = true;

        _storeMock
            .Users
            .FindByIdAsync(auth.Id)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () =>
            await _service.ConfirmTwoFactorAuthActivationAsync(auth, dto));
        Assert.Equal(ErrorCode.LockedAccount, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(auth.Id);
    }

    [Fact]
    public async Task ConfirmTwoFactorAuthActivationAsync_NoAuthenticatorKey_ThrowsAuthException()
    {
        // Arrange
        var auth = _util.AuthUser;
        var dto = new ConfirmTwoFactorAuthActivationDto(_util.Otp);
        var user = _util.User;
        user.Account.Locked = false;
        user.TwoFactorAuth = null;

        _storeMock
            .Users
            .FindByIdAsync(auth.Id)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () =>
            await _service.ConfirmTwoFactorAuthActivationAsync(auth, dto));
        Assert.Equal(ErrorCode.EmptyAuthenticatorKey, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(auth.Id);
    }

    [Fact]
    public async Task ConfirmTwoFactorAuthActivationAsync_AlreadyActivatedTwoFactorAuth_ThrowsAuthException()
    {
        // Arrange
        var auth = _util.AuthUser;
        var dto = new ConfirmTwoFactorAuthActivationDto(_util.Otp);
        var user = _util.User;
        user.Account.Locked = false;
        user.TwoFactorAuth!.Enabled = true;

        _storeMock
            .Users
            .FindByIdAsync(auth.Id)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () =>
            await _service.ConfirmTwoFactorAuthActivationAsync(auth, dto));
        Assert.Equal(ErrorCode.AlreadyActivatedTwoFactorAuth, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(auth.Id);
    }

    [Fact]
    public async Task ConfirmTwoFactorAuthActivationAsync_IncorrectCode_ThrowsAuthException()
    {
        // Arrange
        var auth = _util.AuthUser;
        var dto = new ConfirmTwoFactorAuthActivationDto(_util.Otp);
        var user = _util.User;
        user.Account.Locked = false;
        user.TwoFactorAuth!.Enabled = false;

        _storeMock
            .Users
            .FindByIdAsync(auth.Id)
            .Returns(user);

        _managerMock
            .ValidateTotpCode(user.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode)
            .Returns(false);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () =>
            await _service.ConfirmTwoFactorAuthActivationAsync(auth, dto));
        Assert.Equal(ErrorCode.IncorrectCode, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(auth.Id);

        _managerMock
            .Received(1)
            .ValidateTotpCode(user.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode);
    }

    [Fact]
    public async Task ConfirmTwoFactorAuthActivationAsync_ValidInput_SuccessfullyConfirmTwoFactorAuthActivation()
    {
        // Arrange
        var auth = _util.AuthUser;
        var dto = new ConfirmTwoFactorAuthActivationDto(_util.Otp);
        var user = _util.User;
        user.Account.Locked = false;
        user.TwoFactorAuth!.Enabled = false;

        _storeMock
            .Users
            .FindByIdAsync(auth.Id)
            .Returns(user);

        _managerMock
            .ValidateTotpCode(user.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode)
            .Returns(true);

        // Act
        await _service.ConfirmTwoFactorAuthActivationAsync(auth, dto);

        // Assert
        Assert.True(user.TwoFactorAuth.Enabled);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(auth.Id);

        _managerMock
            .Received(1)
            .ValidateTotpCode(user.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode);

        await _storeMock
            .Received(1)
            .FlushAsync();
    }

    [Fact]
    public async Task DeactivateTwoFactorAuthAsync_InvalidToken_ThrowsAuthException()
    {
        // Arrange
        var auth = _util.AuthUser;
        var dto = new DeactivateTwoFactorAuthDto(_util.Otp);

        _storeMock
            .Users
            .FindByIdAsync(auth.Id)
            .Throws<EntityNotFoundException<User>>();

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () =>
            await _service.DeactivateTwoFactorAuthAsync(auth, dto));
        Assert.Equal(ErrorCode.InvalidToken, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(auth.Id);
    }

    [Fact]
    public async Task DeactivateTwoFactorAuthAsync_LockedAccount_ThrowsAuthException()
    {
        // Arrange
        var auth = _util.AuthUser;
        var dto = new DeactivateTwoFactorAuthDto(_util.Otp);
        var user = _util.User;
        user.Account.Locked = true;

        _storeMock
            .Users
            .FindByIdAsync(auth.Id)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () =>
            await _service.DeactivateTwoFactorAuthAsync(auth, dto));
        Assert.Equal(ErrorCode.LockedAccount, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(auth.Id);
    }

    [Fact]
    public async Task DeactivateTwoFactorAuthAsync_NotActivated_ThrowsAuthException()
    {
        // Arrange
        var auth = _util.AuthUser;
        var dto = new DeactivateTwoFactorAuthDto(_util.Otp);
        var user = _util.User;
        user.Account.Locked = false;
        user.TwoFactorAuth!.Enabled = false;

        _storeMock
            .Users
            .FindByIdAsync(auth.Id)
            .Returns(user);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () =>
            await _service.DeactivateTwoFactorAuthAsync(auth, dto));
        Assert.Equal(ErrorCode.NotActivatedTwoFactorAuth, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(auth.Id);
    }

    [Fact]
    public async Task DeactivateTwoFactorAuthAsync_IncorrectCode_ThrowsAuthException()
    {
        // Arrange
        var auth = _util.AuthUser;
        var dto = new DeactivateTwoFactorAuthDto(_util.Otp);
        var user = _util.User;
        user.Account.Locked = false;
        user.TwoFactorAuth!.Enabled = true;

        _storeMock
            .Users
            .FindByIdAsync(auth.Id)
            .Returns(user);

        _managerMock
            .ValidateTotpCode(user.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode)
            .Returns(false);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () =>
            await _service.DeactivateTwoFactorAuthAsync(auth, dto));
        Assert.Equal(ErrorCode.IncorrectCode, ex.ErrorCode);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(auth.Id);

        _managerMock
            .Received(1)
            .ValidateTotpCode(user.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode);
    }

    [Fact]
    public async Task DeactivateTwoFactorAuthAsync_ValidInput_SuccessfullyDeactivateTwoFactorAuth()
    {
        // Arrange
        var auth = _util.AuthUser;
        var dto = new DeactivateTwoFactorAuthDto(_util.Otp);
        var user = _util.User;
        user.Account.Locked = false;
        user.TwoFactorAuth!.Enabled = true;

        _storeMock
            .Users
            .FindByIdAsync(auth.Id)
            .Returns(user);

        _managerMock
            .ValidateTotpCode(user.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode)
            .Returns(true);

        // Act
        await _service.DeactivateTwoFactorAuthAsync(auth, dto);

        // Assert
        Assert.False(user.TwoFactorAuth.Enabled);

        await _storeMock
            .Users
            .Received(1)
            .FindByIdAsync(auth.Id);

        _managerMock
            .Received(1)
            .ValidateTotpCode(user.TwoFactorAuth.AuthenticatorKey, dto.ConfirmationCode);

        await _storeMock
            .Received(1)
            .FlushAsync();
    }
}