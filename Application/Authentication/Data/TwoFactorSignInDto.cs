using System.ComponentModel.DataAnnotations;

namespace Application.Authentication.Data;

public record TwoFactorSignInDto([Required] string ChallengeKey, [Required] string ConfirmationCode);