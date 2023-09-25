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
    private readonly IKeysManager _keysManagerMock = Substitute.For<IKeysManager>();
    private readonly ITokenProvider _tokenProviderMock = Substitute.For<ITokenProvider>();
    private readonly IPasswordHandler _passwordHandlerMock = Substitute.For<IPasswordHandler>();
    private readonly INotificationSender _notificationSenderMock = Substitute.For<INotificationSender>();

    public AuthServiceTests()
    {
        _util = new TestUtil();

        var options = Options.Create(_util.TokenOptions);
        _service = new AuthService(
            _storeMock,
            options,
            _keysManagerMock,
            _tokenProviderMock,
            _passwordHandlerMock,
            _notificationSenderMock);
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
        _keysManagerMock
            .GenerateTotpCode()
            .Returns(code);

        var encrypted = new EncryptedPassword(_util.Hash, _util.Salt);
        _passwordHandlerMock
            .Encrypt(dto.Password)
            .Returns(encrypted);

        // Act
        await _service.SignUpAsync(dto);

        // Assert
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

        await _notificationSenderMock
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
            .FindByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.RegisterAccount)
            .Throws<EntityNotFoundException<Otp>>();

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ConfirmSignUpAsync(dto));
        Assert.Equal(ErrorCode.IncorrectCode, ex.ErrorCode);
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
            .FindByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.RegisterAccount)
            .Returns(code);

        // Act and Assert
        var ex = await Assert.ThrowsAsync<AuthException>(async () => await _service.ConfirmSignUpAsync(dto));
        Assert.Equal(ErrorCode.ExpiredCode, ex.ErrorCode);
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
            .FindByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.RegisterAccount)
            .Returns(code);

        // Act
        await _service.ConfirmSignUpAsync(dto);

        // Assert
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
        _keysManagerMock
            .GenerateTotpCode()
            .Returns(code);

        // Act
        await _service.ResendSignUpCodeAsync(dto);

        // Assert
        await _storeMock
            .Users
            .Received(1)
            .FindByEmailAsync(dto.Email);

        Assert.Single(user.OneTimePasswords);
        Assert.Equal(code.Content, user.OneTimePasswords.First().Code);
        Assert.Equal(OtpType.RegisterAccount, user.OneTimePasswords.First().Type);
        Assert.Equal(code.IssuedAt.AddMinutes(5), user.OneTimePasswords.First().ExpiredAt);

        await _storeMock
            .Received(1)
            .FlushAsync();

        await _notificationSenderMock
            .Received(1)
            .SendEmailAsync(
                Arg.Is<EmailDto>(email =>
                    email.Receiver == dto.Email &&
                    email.Subject == "Email Confirmation" &&
                    email.Content.Contains(code.Content)));
    }
}