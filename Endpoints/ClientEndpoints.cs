using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using YAuth.Components.Shared;

namespace YAuth.Endpoints;

public record struct NewOpenIdClientRequest(string ClientName);
public record struct OpenIdApplicationDescriptor(string ClientId, string DisplayName, string ClientType);

public class ClientEndpoints : IEndpoint
{
    public static void RegisterRoutes(IEndpointRouteBuilder endpoints)
    {
        var routeGroup = endpoints.MapGroup("client");
        routeGroup.MapGet("/list", ListAllClients);
        routeGroup.MapPost("/", AddClient);
        routeGroup.MapDelete("/", DeleteCLient);
    }

    private static async Task<IResult> AddClient(HttpContext context, [FromServices] ILogger<ClientEndpoints> logger, [FromServices] IOpenIddictApplicationManager applicationManager, [FromForm] NewOpenIdClientRequest request)
    {
        logger.LogInformation("Creating client {ClientName}", request.ClientName);
        var clientName = request.ClientName;

        var rawSecretBytes = new byte[32];
        RandomNumberGenerator.Fill(rawSecretBytes);
        var generatedSecret = Convert.ToBase64String(rawSecretBytes);

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = Guid.NewGuid().ToString(),
            DisplayName = clientName,
        
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ClientSecret = generatedSecret,
        
            RedirectUris = { new Uri("https://localhost:5001/signin-oidc") },

            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.ResponseTypes.Code,
            },
            Requirements =
            {
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
            }
        };
        try
        {
            await applicationManager.CreateAsync(descriptor);
        }
        catch (Exception e)
        {
            logger.LogError(e, "Error creating client");
            return Results.BadRequest(e);
        }
        
        context.Response.Headers.Append("HX-Trigger", "refreshClientList");

        return Results.Ok();
    }

    private static async Task<IResult> DeleteCLient([FromServices] ILogger<ClientEndpoints> logger,
        [FromServices] IOpenIddictApplicationManager applicationManager, HttpContext context, [FromQuery] string clientId)
    {
        var application = await applicationManager.FindByClientIdAsync(clientId);
    
        if (application is null)
        {
            return Results.NotFound();
        }

        await applicationManager.DeleteAsync(application);

        context.Response.Headers.Append("HX-Trigger", "refreshClientList");

        return Results.Ok();
    }

    private static async Task<IResult> ListAllClients([FromServices] ILogger<ClientEndpoints> logger,
        [FromServices] IOpenIddictApplicationManager applicationManager)
    {
        var clientList = new List<OpenIdApplicationDescriptor>();

        try
        {
            await foreach (var app in applicationManager.ListAsync())
            {
                clientList.Add(new OpenIdApplicationDescriptor
                {
                    ClientId = await applicationManager.GetClientIdAsync(app) ?? "Unknown",
                    DisplayName = await applicationManager.GetDisplayNameAsync(app) ?? "Unnamed App",
                    ClientType = await applicationManager.GetClientTypeAsync(app) ?? "Unknown"
                });
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "An error occurred while fetching OpenIddict applications.");
            return Results.Problem("Unable to load client inventories.");
        }
        
        return new RazorComponentResult<OpenIdClientList>(new { Model = clientList });
    } 
}