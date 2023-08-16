using System.ComponentModel.DataAnnotations;

namespace Application.Authentication.Data;

public record DeactivateTwoFactorAuthDto([Required] string ConfirmationCode);