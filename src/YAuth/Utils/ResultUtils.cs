using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Net.Http.Headers;
using YAuth.Components.Shared;

namespace YAuth.Utils;

public static class ResultUtils
{
    extension(Results)
    {
        public static IResult HtmxRedirect(string url)
        {
            return new HtmxRedirectResult(url);
        }

        public static IResult ValidationError(string title, IEnumerable<string>? messages = null)
        {
            return new ValidationErrorResult(title, messages);
        }
    }

    private class HtmxRedirectResult(string url) : IResult
    {
        public Task ExecuteAsync(HttpContext httpContext)
        {
            httpContext.Response.Headers["HX-Redirect"] = url;
            httpContext.Response.StatusCode = 200;
            return Task.CompletedTask;
        }
    }

    private class ValidationErrorResult(string title, IEnumerable<string>? messages = null) : IResult
    {
        public Task ExecuteAsync(HttpContext httpContext)
        {
            var args = new Dictionary<string, object?>
            {
                { "Title", title },
                { "Messages", messages }
            };
            httpContext.Response.StatusCode = StatusCodes.Status400BadRequest;
            return new RazorComponentResult<ValidationError>(args).ExecuteAsync(httpContext);
        }
    }
}