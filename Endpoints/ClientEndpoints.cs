using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using YAuth.Components.Shared;
using YAuth.Data;
using YAuth.Extensions;

namespace YAuth.Endpoints;

public record NewOpenIdClientRequest
{
    [Required] public string ClientName { get; init; } = string.Empty;
};

public abstract class ClientEndpoints : IEndpoint
{
    public static void RegisterRoutes(IEndpointRouteBuilder endpoints)
    {
        var routeGroup = endpoints.MapGroup("client");
        routeGroup.MapGet("/list", ListAllClients).RequireAuthorization(Policies.AdminPolicy);
        routeGroup.MapPost("/create", AddClient).RequireAuthorization(Policies.AdminPolicy);
        routeGroup.MapDelete("/", DeleteClient).RequireAuthorization(Policies.AdminPolicy);
    }

    private static async Task<IResult> AddClient(
        [FromForm] NewOpenIdClientRequest request,
        HttpContext context,
        [FromServices] ILogger<ClientEndpoints> logger,
        [FromServices] IOpenIddictApplicationManager applicationManager)
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

        context.HxTrigger("refreshClientList");

        return Results.Ok();
    }

    private static async Task<IResult> DeleteClient(
        [FromServices] ILogger<ClientEndpoints> logger,
        [FromServices] IOpenIddictApplicationManager applicationManager,
        HttpContext context,
        [FromQuery] string clientId)
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

    private static async Task<IResult> ListAllClients(
        [FromServices] ILogger<ClientEndpoints> logger,
        [FromServices] IOpenIddictApplicationManager applicationManager)
    {
        var clientList = new List<OpenIddictEntityFrameworkCoreApplication>();

        try
        {
            await foreach (var app in applicationManager.ListAsync())
            {
                clientList.Add((OpenIddictEntityFrameworkCoreApplication)app);
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