using System.ComponentModel.DataAnnotations;
using Application.Authentication.Validation;

namespace Application.Authentication.Data;

public record SignUpDto(
    [Required, EmailAddress] string Email,
    [Required, Username] string Username,
    [Required, Password] string Password);