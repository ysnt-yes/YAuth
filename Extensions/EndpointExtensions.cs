using System.Reflection;
using YAuth.Endpoints;

namespace YAuth.Extensions;

public static class EndpointExtensions
{
    public static void MapEndpoints(this IEndpointRouteBuilder app)
    {
        var endpointTypes = Assembly.GetExecutingAssembly()
            .GetTypes()
            .Where(t => t is { IsClass: true, IsAbstract: false } && t.IsAssignableTo(typeof(IEndpoint)));

        foreach (var type in endpointTypes)
        {
            var method = type.GetMethod(nameof(IEndpoint.RegisterRoutes), BindingFlags.Public | BindingFlags.Static);
            method?.Invoke(null, [app]);
        }
    }
}