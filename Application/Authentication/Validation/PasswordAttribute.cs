using System.ComponentModel.DataAnnotations;

namespace Application.Authentication.Validation;

public class PasswordAttribute : RegularExpressionAttribute
{
    // at least: 10 characters, three capital letters, one lowercase letter,  
    // two digits, three special characters. 
    private const string RegEx =
        "^(?=(.*[A-Z]){3,})(?=(.*[a-z]){1,})(?=(.*[0-9]){2,})(?=(.*[!#$%&()*+,-./:;<=>?@_{|}~^]){3,})(.{9,}).+$";

    public PasswordAttribute() : base(RegEx)
    {
    }
}