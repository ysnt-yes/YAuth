using System.Reflection;
using YAuth.Endpoints;

namespace YAuth.Extensions;

public static class EndpointExtensions
{
    public static void MapYAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var authGroup = endpoints.MapGroup("auth");
        AuthEndpoints.RegisterRoutes(authGroup);
        
        var apiGroup = endpoints.MapGroup("api");
        ClientEndpoints.RegisterRoutes(apiGroup);
        ApiEndpoints.RegisterRoutes(apiGroup);
        UsersEndpoints.RegisterRoutes(apiGroup);
        
        var oidcGroup = endpoints.MapGroup("oidc");
        OidcEndpoints.RegisterRoutes(oidcGroup);
    }
}