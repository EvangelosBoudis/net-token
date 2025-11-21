using System.ComponentModel.DataAnnotations;

namespace Application.Authentication.Data;

public record ResendSignUpCodeDto([Required, EmailAddress] string Email);