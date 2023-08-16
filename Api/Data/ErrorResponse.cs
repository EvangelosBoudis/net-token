namespace Api.Data;

public record ErrorResponse(string Code, string? Description, Dictionary<string, string[]>? Details = null);