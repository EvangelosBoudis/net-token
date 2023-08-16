using System.ComponentModel.DataAnnotations;
using Application.Authentication.Validation;

namespace Application.Authentication.Data;

public record ConfirmResetPasswordDto(
    [Required, EmailAddress] string Email,
    [Required, Password] string Password,
    [Required] string ConfirmationCode);