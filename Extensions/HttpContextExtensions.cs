namespace YAuth.Extensions;

public static class HttpContextExtensions
{
    public static void HxTrigger(this HttpContext context, string trigger)
    {
        context.Response.Headers.Append("HX-Trigger", trigger);
    }
}