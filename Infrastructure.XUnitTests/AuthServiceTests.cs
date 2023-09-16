using Application.Authentication.Data;
using Application.Authentication.Exceptions;
using Application.Keys;
using Application.Notification;
using Application.Notification.Data;
using Application.Password;
using Application.Password.Data;
using Application.Store;
using Application.Token;
using Domain.Entities;
using Domain.Enums;
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
    public async Task SignUpAsync_UserDoesNotExist_SuccessfullyRegistersUser()
    {
        // Arrange
        var otpCode = _dataMock.User.Otp;
        var signUp = new SignUpDto(_dataMock.User.Email, _dataMock.User.Name, _dataMock.User.Password);
        var encryptedPassword = new EncryptedPassword(_dataMock.User.Hash, _dataMock.User.Salt);

        _storeMock
            .Setup(mock => mock.Users.ExistsByUsernameOrEmailAsync(signUp.Username, signUp.Email))
            .ReturnsAsync(false);

        _keysManagerMock
            .Setup(mock => mock.GenerateTotpCode())
            .Returns(otpCode);

        _passwordHandlerMock
            .Setup(mock => mock.Encrypt(signUp.Password))
            .Returns(encryptedPassword);

        // Act
        await _service.SignUpAsync(signUp);

        // Assert
        _storeMock.Verify(mock => mock.Users.SaveAsync(It.Is<User>(user =>
            user.Username == signUp.Username &&
            user.Email == signUp.Email &&
            user.PasswordHash == encryptedPassword.Hash &&
            user.PasswordSalt == encryptedPassword.Salt &&
            user.OneTimePasswords.Count == 1 &&
            user.OneTimePasswords.First().Code == otpCode &&
            user.OneTimePasswords.First().Type == OtpType.RegisterAccount &&
            user.OneTimePasswords.First().ExpiredAt > DateTime.UtcNow)
        ), Times.Once);

        _storeMock.Verify(mock => mock.FlushAsync(), Times.Once);

        _notificationSenderMock.Verify(mock => mock.SendEmailAsync(
            It.Is<EmailDto>(email =>
                email.Receiver == signUp.Email &&
                email.Subject == "Email Confirmation" &&
                email.Content.Contains(otpCode))
        ), Times.Once);
    }

    [Fact]
    public async Task SignUpAsync_UserAlreadyExists_ThrowsAuthException()
    {
        // Arrange
        var signUp = new SignUpDto(_dataMock.User.Email, _dataMock.User.Name, _dataMock.User.Password);

        _storeMock
            .Setup(mock => mock.Users.ExistsByUsernameOrEmailAsync(signUp.Username, signUp.Email))
            .ReturnsAsync(true);

        // Act & Assert
        await Assert.ThrowsAsync<AuthException>(() => _service.SignUpAsync(signUp));
    }
}