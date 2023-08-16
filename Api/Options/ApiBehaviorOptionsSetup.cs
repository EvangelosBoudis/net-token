using Api.Data;
using Domain.Exceptions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Api.Options;

public class ApiBehaviorOptionsSetup : IConfigureOptions<ApiBehaviorOptions>
{
    public void Configure(ApiBehaviorOptions options)
    {
        options.InvalidModelStateResponseFactory = context =>
        {
            var errors = context.ModelState
                .Select(entry => new
                    { key = entry.Key, value = entry.Value!.Errors.Select(er => er.ErrorMessage).ToArray() })
                .ToDictionary(entry => entry.key, entry => entry.value);

            var response = new ErrorResponse(
                ErrorCode.InvalidBodyRequest,
                "One or more validation errors occurred.",
                errors);

            var result = new BadRequestObjectResult(response);
            result.ContentTypes.Add("application/json");
            return result;
        };
    }
}