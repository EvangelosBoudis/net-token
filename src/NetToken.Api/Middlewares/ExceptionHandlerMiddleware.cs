using System.Net;
using Application.Authentication.Exceptions;
using Domain.Exceptions;
using NetToken.Api.Data;

namespace NetToken.Api.Middlewares;

public class ExceptionHandlerMiddleware : IMiddleware
{
    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        try
        {
            await next(context);
            if (context.Response.StatusCode == (int)HttpStatusCode.Unauthorized)
            {
                const string key = "error_description=";
                var message = context.Response.Headers["WWW-Authenticate"].ToString();
                var description = message[(message.IndexOf(key, StringComparison.Ordinal) + key.Length)..]
                    .Replace("\"", string.Empty);
                await context.Response.WriteAsJsonAsync(
                    new ErrorResponse(ErrorCode.InvalidToken, description));
            }
        }
        catch (AuthException error)
        {
            context.Response.StatusCode = (int)HttpStatusCode.BadRequest;
            await context.Response.WriteAsJsonAsync(
                new ErrorResponse(error.ErrorCode, "An authentication error has occurred"));
        }
    }
}