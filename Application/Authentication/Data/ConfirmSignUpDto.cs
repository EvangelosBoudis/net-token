using System.ComponentModel.DataAnnotations;

namespace Application.Authentication.Data;

public record ConfirmSignUpDto([Required, EmailAddress] string Email, [Required] string ConfirmationCode);