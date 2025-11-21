using System.ComponentModel.DataAnnotations;

namespace Application.Authentication.Data;

public record ResetPasswordDto([Required, EmailAddress] string Email);