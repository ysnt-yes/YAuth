namespace YAuth.Endpoints;

public interface IEndpoint
{
    public static abstract void RegisterRoutes(IEndpointRouteBuilder endpoints);
}