using System.Security.Claims;
using Application.Token.Data;
using Domain.Data;

namespace Forteio.Identity.Authentication.Extensions;

public static class ClaimsPrincipalExtensions
{
    public static AuthUser ToAuthUser(this ClaimsPrincipal principal)
    {
        var id = new Guid(principal.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var email = principal.FindFirstValue(ClaimTypes.Email)!;
        var name = principal.FindFirstValue(ClaimTypes.Name)!;
        var phoneNumber = principal.FindFirstValue(TokenClaimNames.PhoneNumber) ?? "false";
        var phoneNumberVerified = bool.Parse(principal.FindFirstValue(TokenClaimNames.PhoneNumberVerified) ?? "false");
        var twoFactorEnabled = bool.Parse(principal.FindFirstValue(TokenClaimNames.TwoFactorEnabled) ?? "false");

        return new AuthUser(id, email, name, phoneNumber, phoneNumberVerified, twoFactorEnabled);
    }
}