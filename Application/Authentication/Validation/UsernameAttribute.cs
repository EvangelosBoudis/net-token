using System.ComponentModel.DataAnnotations;

namespace Application.Authentication.Validation;

public class UsernameAttribute : ValidationAttribute
{
    public override bool IsValid(object? value)
    {
        if (value is string str) return str.Length is > 3 and < 15;
        return false;
    }
}