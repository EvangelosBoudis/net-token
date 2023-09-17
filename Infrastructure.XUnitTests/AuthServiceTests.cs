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

    private readonly MockData _dataMock;
    private readonly Mock<IStore> _storeMock = new();
    private readonly Mock<IKeysManager> _keysManagerMock = new();
    private readonly Mock<ITokenProvider> _tokenProviderMock = new();
    private readonly Mock<IPasswordHandler> _passwordHandlerMock = new();
    private readonly Mock<INotificationSender> _notificationSenderMock = new();

    public AuthServiceTests()
    {
        _dataMock = new TestUtil().MockData;

        _service = new AuthService(
            _storeMock.Object,
            Options.Create(_dataMock.Token),
            _keysManagerMock.Object,
            _tokenProviderMock.Object,
            _passwordHandlerMock.Object,
            _notificationSenderMock.Object);
    }

    [Fact]
    public async Task SignUpAsync_UserAlreadyExists_ThrowsAuthException()
    {
        // Arrange
        var dto = new SignUpDto(_dataMock.User.Email, _dataMock.User.Name, _dataMock.User.Password);

        _storeMock
            .Setup(mock => mock.Users.ExistsByUsernameOrEmailAsync(dto.Username, dto.Email))
            .ReturnsAsync(true);

        // Act & Assert
        await Assert.ThrowsAsync<AuthException>(() => _service.SignUpAsync(dto));
    }

    [Fact]
    public async Task SignUpAsync_UserDoesNotExist_SuccessfullyRegistersUser()
    {
        // Arrange
        var code = new TotpCode(_dataMock.User.Otp, DateTime.Now);
        var dto = new SignUpDto(_dataMock.User.Email, _dataMock.User.Name, _dataMock.User.Password);
        var encrypted = new EncryptedPassword(_dataMock.User.Hash, _dataMock.User.Salt);

        _storeMock
            .Setup(mock => mock.Users.ExistsByUsernameOrEmailAsync(dto.Username, dto.Email))
            .ReturnsAsync(false);

        _keysManagerMock
            .Setup(mock => mock.GenerateTotpCode())
            .Returns(code);

        _passwordHandlerMock
            .Setup(mock => mock.Encrypt(dto.Password))
            .Returns(encrypted);

        // Act
        await _service.SignUpAsync(dto);

        // Assert
        _storeMock.Verify(mock => mock.Users.SaveAsync(It.Is<User>(user =>
            user.Username == dto.Username &&
            user.Email == dto.Email &&
            user.PasswordHash == encrypted.Hash &&
            user.PasswordSalt == encrypted.Salt &&
            user.OneTimePasswords.Count == 1 &&
            user.OneTimePasswords.First().Code == code.Content &&
            user.OneTimePasswords.First().Type == OtpType.RegisterAccount &&
            user.OneTimePasswords.First().ExpiredAt == code.IssuedAt.AddMinutes(5))
        ), Times.Once);

        _storeMock.Verify(mock => mock.FlushAsync(), Times.Once);

        _notificationSenderMock.Verify(mock => mock.SendEmailAsync(
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
        var dto = new ConfirmSignUpDto(_dataMock.User.Email, _dataMock.User.Otp);

        _storeMock
            .Setup(mock => mock.Users.FindByEmailAsync(dto.Email))
            .Throws<EntityNotFoundException<User>>();

        // Act & Assert
        await Assert.ThrowsAsync<AuthException>(() => _service.ConfirmSignUpAsync(dto));
    }

    [Fact]
    public async Task ConfirmSignUpAsync_AlreadyConfirmedAccount_ThrowsAuthException()
    {
        // Arrange
        var dto = new ConfirmSignUpDto(_dataMock.User.Email, _dataMock.User.Otp);

        var user = new User
        {
            Id = Guid.NewGuid(),
            Username = _dataMock.User.Name,
            Email = dto.Email,
            Account = new Account
            {
                Confirmed = true
            },
            PasswordHash = _dataMock.User.Hash,
            PasswordSalt = _dataMock.User.Salt
        };

        _storeMock
            .Setup(mock => mock.Users.FindByEmailAsync(dto.Email))
            .ReturnsAsync(user);

        // Act & Assert
        await Assert.ThrowsAsync<AuthException>(() => _service.ConfirmSignUpAsync(dto));
    }

    [Fact]
    public async Task ConfirmSignUpAsync_IncorrectCode_ThrowsAuthException()
    {
        // Arrange
        var dto = new ConfirmSignUpDto(_dataMock.User.Email, _dataMock.User.Otp);

        var user = new User
        {
            Id = Guid.NewGuid(),
            Username = _dataMock.User.Name,
            Email = dto.Email,
            Account = new Account
            {
                Confirmed = false
            },
            PasswordHash = _dataMock.User.Hash,
            PasswordSalt = _dataMock.User.Salt
        };

        _storeMock
            .Setup(mock => mock.Users.FindByEmailAsync(dto.Email))
            .ReturnsAsync(user);

        _storeMock
            .Setup(mock =>
                mock.Otp.FindByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.RegisterAccount))
            .Throws<EntityNotFoundException<Otp>>();

        // Act & Assert
        await Assert.ThrowsAsync<AuthException>(() => _service.ConfirmSignUpAsync(dto));
    }

    [Fact]
    public async Task ConfirmSignUpAsync_ExpiredCode_ThrowsAuthException()
    {
        // Arrange
        var dto = new ConfirmSignUpDto(_dataMock.User.Email, _dataMock.User.Otp);

        var user = new User
        {
            Id = Guid.NewGuid(),
            Username = _dataMock.User.Name,
            Email = dto.Email,
            Account = new Account
            {
                Confirmed = false
            },
            PasswordHash = _dataMock.User.Hash,
            PasswordSalt = _dataMock.User.Salt
        };

        var code = new Otp
        {
            UserId = user.Id,
            Code = dto.ConfirmationCode,
            Type = OtpType.RegisterAccount,
            ExpiredAt = DateTime.UtcNow
        };

        _storeMock
            .Setup(mock => mock.Users.FindByEmailAsync(dto.Email))
            .ReturnsAsync(user);

        _storeMock
            .Setup(mock =>
                mock.Otp.FindByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.RegisterAccount))
            .ReturnsAsync(code);

        // Act & Assert
        await Assert.ThrowsAsync<AuthException>(() => _service.ConfirmSignUpAsync(dto));
    }

    [Fact]
    public async Task ConfirmSignUpAsync_ValidInput_ConfirmsSignUp()
    {
        // Arrange
        var dto = new ConfirmSignUpDto(_dataMock.User.Email, _dataMock.User.Otp);

        var user = new User
        {
            Id = Guid.NewGuid(),
            Username = _dataMock.User.Name,
            Email = dto.Email,
            Account = new Account
            {
                Confirmed = false
            },
            PasswordHash = _dataMock.User.Hash,
            PasswordSalt = _dataMock.User.Salt
        };

        var code = new Otp
        {
            UserId = user.Id,
            Code = dto.ConfirmationCode,
            Type = OtpType.RegisterAccount,
            ExpiredAt = DateTime.UtcNow.AddMinutes(5)
        };

        _storeMock
            .Setup(mock => mock.Users.FindByEmailAsync(dto.Email))
            .ReturnsAsync(user);

        _storeMock
            .Setup(mock =>
                mock.Otp.FindByUserIdCodeAndTypeAsync(user.Id, dto.ConfirmationCode, OtpType.RegisterAccount))
            .ReturnsAsync(code);

        // Act
        await _service.ConfirmSignUpAsync(dto);

        // Assert
        Assert.True(user.EmailConfirmed);
        Assert.True(user.Account.Confirmed);
        Assert.True(code.Redeemed);

        _storeMock.Verify(mock => mock.FlushAsync(), Times.Once);
    }
}