using System.ComponentModel.DataAnnotations;
using Application.Authentication.Validation;

namespace Application.Authentication.Data;

public record SignInDto([Required] string Email, [Required, Password] string Password);