using System.ComponentModel.DataAnnotations;

namespace Application.Authentication.Data;

public record ConfirmTwoFactorAuthActivationDto([Required] string ConfirmationCode);