using Domain.Data;

namespace Application.Authentication.Data;

public record SignInResult(TokenData? Token = null, string? ChallengeKey = null, bool SignedIn = true);