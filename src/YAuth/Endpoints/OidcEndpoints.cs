using System.Security.Claims;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using YAuth.Data;

namespace YAuth.Endpoints;

public abstract class OidcEndpoints : IEndpoint
{
    public static void RegisterRoutes(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/connect/authorize", async (
            [FromServices] HttpContext context,
            [FromServices] SignInManager<User> signInManager) =>
        {
            var request = context.GetOpenIddictServerRequest() ??
                          throw new InvalidOperationException("The OpenIddict server request cannot be retrieved.");

            var user = await signInManager.UserManager.GetUserAsync(context.User);

            if (user is null)
            {
                var loginUrl =
                    $"/login?returnUrl={Uri.EscapeDataString(context.Request.Path + context.Request.QueryString)}";
                return Results.Redirect(loginUrl);
            }

            var identity = new ClaimsIdentity(
                TokenValidationParameters.DefaultAuthenticationType,
                OpenIddictConstants.Claims.Name,
                OpenIddictConstants.Claims.Role);

            identity.SetClaim(OpenIddictConstants.Claims.Subject,
                await signInManager.UserManager.GetUserIdAsync(user));

            identity.SetClaim(OpenIddictConstants.Claims.Name,
                await signInManager.UserManager.GetUserNameAsync(user));

            identity.SetClaim(OpenIddictConstants.Claims.Email,
                await signInManager.UserManager.GetEmailAsync(user));


            var roles = await signInManager.UserManager.GetRolesAsync(user);

            foreach (var role in roles)
            {
                identity.AddClaim(new Claim(OpenIddictConstants.Claims.Role, role));
            }


            identity.SetDestinations(claim => claim.Type switch
            {
                OpenIddictConstants.Claims.Email =>
                    [OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken],
                OpenIddictConstants.Claims.Role =>
                [
                    OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken
                ],
                _ => [OpenIddictConstants.Destinations.AccessToken]
            });

            var principal = new ClaimsPrincipal(identity);

            return Results.SignIn(principal, properties: null,
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        });

        endpoints.MapPost("/connect/token", async (HttpContext context, [FromServices] SignInManager<User> signInManager) =>
        {
            var request = context.GetOpenIddictServerRequest() ??
                          throw new InvalidOperationException("The OpenIddict server request cannot be retrieved.");

            if (request.IsClientCredentialsGrantType())
            {
                var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
                identity.SetClaim(OpenIddictConstants.Claims.Subject, request.ClientId);

                var ccPrincipal = new ClaimsPrincipal(identity);
                ccPrincipal.SetScopes(request.GetScopes());

                return Results.SignIn(ccPrincipal, properties: null,
                    OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
                throw new InvalidOperationException("The specified grant type is not supported.");


            var result = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var codePrincipal = result.Principal;

            if (codePrincipal is null)
            {
                return Results.BadRequest(new OpenIddictResponse
                {
                    Error = OpenIddictConstants.Errors.InvalidGrant,
                    ErrorDescription = "The token or authorization code is invalid."
                });
            }

            var userId = codePrincipal.GetClaim(OpenIddictConstants.Claims.Subject);
            if (string.IsNullOrEmpty(userId))
            {
                return Results.BadRequest(new OpenIddictResponse
                {
                    Error = OpenIddictConstants.Errors.InvalidGrant,
                    ErrorDescription = "The token claims are malformed."
                });
            }

            var user = await signInManager.UserManager.FindByIdAsync(userId);
            if (user is null || !await signInManager.CanSignInAsync(user))
            {
                return Results.BadRequest(new OpenIddictResponse
                {
                    Error = OpenIddictConstants.Errors.InvalidGrant,
                    ErrorDescription = "The user is no longer allowed to sign in."
                });
            }

            return Results.SignIn(codePrincipal, properties: null,
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        });


        endpoints.MapGet("/connect/userinfo", async (HttpContext context, UserManager<User> userManager) =>
        {
            var result = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            if (!result.Succeeded)
            {
                return Results.Challenge(properties: null,
                    [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
            }

            var user = await userManager.FindByIdAsync(
                result.Principal.GetClaim(OpenIddictConstants.Claims.Subject)!);
            if (user is null)
            {
                return Results.Challenge(properties: null,
                    [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
            }

            var claims = new Dictionary<string, object>
            {
                [OpenIddictConstants.Claims.Subject] = await userManager.GetUserIdAsync(user),
                [OpenIddictConstants.Claims.Name] = await userManager.GetUserNameAsync(user) ?? "",
                [OpenIddictConstants.Claims.Email] = await userManager.GetEmailAsync(user) ?? ""
            };

            return Results.Ok(claims);
        }).RequireAuthorization();
    }
}