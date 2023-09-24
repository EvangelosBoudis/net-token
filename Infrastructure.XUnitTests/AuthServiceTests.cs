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
using Infrastructure.XUnitTests.Utils;
using Microsoft.Extensions.Options;
using Moq;

namespace Infrastructure.XUnitTests;

public class AuthServiceTests
{
    private readonly AuthService _service;

    private readonly TestUtil _util;
    private readonly Mock<IStore> _storeMock = new();
    private readonly Mock<IKeysManager> _keysManagerMock = new();
    private readonly Mock<ITokenProvider> _tokenProviderMock = new();
    private readonly Mock<IPasswordHandler> _passwordHandlerMock = new();
    private readonly Mock<INotificationSender> _notificationSenderMock = new();

    public AuthServiceTests()
    {
        _util = new TestUtil();

        var options = Options.Create(_util.TokenOptions);
        _service = new AuthService(
            _storeMock.Object,
            options,
            _keysManagerMock.Object,
            _tokenProviderMock.Object,
            _passwordHandlerMock.Object,
            _notificationSenderMock.Object);
    }

    [Fact]
    public async Task SignUpAsync_UserAlreadyExists_ThrowsAuthException()
    {
        // Arrange
        var dto = new SignUpDto(_util.Email, _util.Name, _util.Password);

        _storeMock
            .Setup(store => store.Users.ExistsByUsernameOrEmailAsync(dto.Username, dto.Email))
            .ReturnsAsync(true);

        // Act and Assert
        await Assert.ThrowsAsync<AuthException>(async () => await _service.SignUpAsync(dto));
    }

    [Fact]
    public async Task SignUpAsync_ValidInput_SuccessfullyRegistersUser()
    {
        // Arrange
        var dto = new SignUpDto(_util.Email, _util.Name, _util.Password);

        _storeMock
            .Setup(store => store.Users.ExistsByUsernameOrEmailAsync(dto.Username, dto.Email))
            .ReturnsAsync(false);

        var code = new TotpCode(_util.Otp, DateTime.UtcNow);
        _keysManagerMock
            .Setup(manager => manager.GenerateTotpCode())
            .Returns(code);

        var encrypted = new EncryptedPassword(_util.Hash, _util.Salt);
        _passwordHandlerMock
            .Setup(handler => handler.Encrypt(dto.Password))
            .Returns(encrypted);

        // Act
        await _service.SignUpAsync(dto);

        // Assert
        _storeMock.Verify(store => store.Users.SaveAsync(It.Is<User>(user =>
            user.Username == dto.Username &&
            user.Email == dto.Email &&
            user.PasswordHash == encrypted.Hash &&
            user.PasswordSalt == encrypted.Salt &&
            user.OneTimePasswords.Count == 1 &&
            user.OneTimePasswords.First().Code == code.Content &&
            user.OneTimePasswords.First().Type == OtpType.RegisterAccount &&
            user.OneTimePasswords.First().ExpiredAt == code.IssuedAt.AddMinutes(5))
        ), Times.Once);

        _storeMock.Verify(store => store.FlushAsync(), Times.Once);

        _notificationSenderMock.Verify(sender => sender.SendEmailAsync(
            It.Is<EmailDto>(email =>
                email.Receiver == dto.Email &&
                email.Subject == "Email Confirmation" &&
                email.Content.Contains(code.Content))
        ), Times.Once);
    }

    [Fact]
    public async Task ConfirmSignUpAsync_IncorrectEmail_ThrowsAuthException()
    {
        // Arrange
        var dto = new ConfirmSignUpDto(_util.Email, _util.Otp);

        _storeMock
            .Setup(store => store.Users.FindByEmailAsync(dto.Email))
            .Throws<EntityNotFoundException<User>>();

        // Act and Assert
        await Assert.ThrowsAsync<AuthException>(async () => await _service.ConfirmSignUpAsync(dto));
    }

    [Fact]
    public async Task ConfirmSignUpAsync_AlreadyConfirmedAccount_ThrowsAuthException()
    {
        // Arrange
        var dto = new ConfirmSignUpDto(_util.Email, _util.Otp);
        var user = _util.User;
        user.Account.Confirmed = true;

        _storeMock
            .Setup(store => store.Users.FindByEmailAsync(dto.Email))
            .ReturnsAsync(user);

        // Act and Assert
        await Assert.ThrowsAsync<AuthException>(async () => await _service.ConfirmSignUpAsync(dto));
    }

    [Fact]
    public async Task ConfirmSignUpAsync_IncorrectCode_ThrowsAuthException()
    {
        // Arrange
        var dto = new ConfirmSignUpDto(_util.Email, _util.Otp);
        var user = _util.User;
        user.Account.Confirmed = false;

        _storeMock
            .Setup(store => store.Users.FindByEmailAsync(dto.Email))
            .ReturnsAsync(user);

        _storeMock
            .Setup(store =>
                store.Otp.FindByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.RegisterAccount))
            .Throws<EntityNotFoundException<Otp>>();

        // Act and Assert
        await Assert.ThrowsAsync<AuthException>(async () => await _service.ConfirmSignUpAsync(dto));
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
            .Setup(store => store.Users.FindByEmailAsync(dto.Email))
            .ReturnsAsync(user);

        _storeMock
            .Setup(store =>
                store.Otp.FindByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.RegisterAccount))
            .ReturnsAsync(code);

        // Act and Assert
        await Assert.ThrowsAsync<AuthException>(async () => await _service.ConfirmSignUpAsync(dto));
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
            .Setup(store => store.Users.FindByEmailAsync(dto.Email))
            .ReturnsAsync(user);

        _storeMock
            .Setup(store =>
                store.Otp.FindByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.RegisterAccount))
            .ReturnsAsync(code);

        // Act
        await _service.ConfirmSignUpAsync(dto);

        // Assert
        Assert.True(user.EmailConfirmed);
        Assert.True(user.Account.Confirmed);
        Assert.True(code.Redeemed);

        _storeMock.Verify(store => store.FlushAsync(), Times.Once);
    }

    [Fact]
    public async Task ResendSignUpCodeAsync_IncorrectEmail_ThrowsAuthException()
    {
        // Arrange
        var dto = new ResendSignUpCodeDto(_util.Email);

        _storeMock
            .Setup(store => store.Users.FindByEmailAsync(dto.Email))
            .Throws(new EntityNotFoundException<User>());

        // Act and Assert
        await Assert.ThrowsAsync<AuthException>(async () => await _service.ResendSignUpCodeAsync(dto));
    }

    [Fact]
    public async Task ResendSignUpCodeAsync_AlreadyConfirmedAccount_ThrowsAuthException()
    {
        // Arrange
        var dto = new ResendSignUpCodeDto(_util.Email);
        var user = _util.User;
        user.Account.Confirmed = true;

        _storeMock
            .Setup(store => store.Users.FindByEmailAsync(dto.Email))
            .ReturnsAsync(user);

        // Act and Assert
        await Assert.ThrowsAsync<AuthException>(async () => await _service.ResendSignUpCodeAsync(dto));
    }

    [Fact]
    public async Task ResendSignUpCodeAsync_ValidInput_SuccessfullyResendsCodeAndEmail()
    {
        // Arrange
        var dto = new ResendSignUpCodeDto(_util.Email);
        var user = _util.User;
        user.Account.Confirmed = false;

        _storeMock
            .Setup(store => store.Users.FindByEmailAsync(dto.Email))
            .ReturnsAsync(user);

        _storeMock
            .Setup(store => store.Otp.UpdateAsDisabledActiveCodesAsync(user.Id, OtpType.RegisterAccount))
            .Returns(Task.CompletedTask);

        var code = new TotpCode(_util.Otp, DateTime.UtcNow);
        _keysManagerMock
            .Setup(manager => manager.GenerateTotpCode())
            .Returns(code);

        // Act
        await _service.ResendSignUpCodeAsync(dto);

        // Assert
        Assert.Single(user.OneTimePasswords);
        Assert.Equal(code.Content, user.OneTimePasswords.First().Code);
        Assert.Equal(OtpType.RegisterAccount, user.OneTimePasswords.First().Type);
        Assert.Equal(code.IssuedAt.AddMinutes(5), user.OneTimePasswords.First().ExpiredAt);

        _storeMock.Verify(store => store.FlushAsync(), Times.Once);

        _notificationSenderMock.Verify(sender => sender.SendEmailAsync(
            It.Is<EmailDto>(email =>
                email.Receiver == dto.Email &&
                email.Subject == "Email Confirmation" &&
                email.Content.Contains(code.Content))
        ), Times.Once);
    }
}