using System.ComponentModel.DataAnnotations;
using Application.Authentication.Validation;

namespace Application.Authentication.Data;

public record ModifyPasswordDto([Required] string CurrentPassword, [Required, Password] string Password);