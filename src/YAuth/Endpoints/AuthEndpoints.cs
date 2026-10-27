using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Client.AspNetCore;
using YAuth.Data;
using YAuth.Utils;

namespace YAuth.Endpoints;

public record LoginDto
{
    [Required] public string Username { get; init; } = string.Empty;

    [Required]
    [DataType(DataType.Password)]
    public string Password { get; init; } = string.Empty;

    public void Deconstruct(out string username, out string password)
    {
        username = Username;
        password = Password;
    }
}

public abstract class AuthEndpoints : IEndpoint
{
    public static void RegisterRoutes(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/login", async (
            [FromForm] LoginDto loginDto,
            [FromForm] string? returnUrl,
            [FromServices] SignInManager<User> signInManager,
            [FromServices] ILogger<AuthEndpoints> logger) =>
        {
            var (username, password) = loginDto;
            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            {
                return Results.ValidationError("Please enter a username and password.");
            }

            var result =
                await signInManager.PasswordSignInAsync(username, password, isPersistent: true, lockoutOnFailure: true);

            if (result.IsLockedOut)
            {
                return Results.ValidationError("This account has been locked due to too many failures.");
            }

            if (!result.Succeeded)
            {
                return Results.ValidationError("Invalid username or password.");
            }

            var redirectTarget = !string.IsNullOrWhiteSpace(returnUrl) ? returnUrl : "/";
            return Results.HtmxRedirect(redirectTarget);
        });

        endpoints.MapPost("/logout", async (SignInManager<User> signinManager) =>
        {
            await signinManager.SignOutAsync();
            return Results.Redirect("/");
        });

        endpoints.MapPost("/register", async (
            [FromForm] string username,
            [FromForm] string email,
            [FromForm] string password,
            [FromServices] UserManager<User> userManager,
            [FromServices] IConfiguration configuration) =>
        {
            var allowRegistration = configuration.GetValue("Authentication:AllowRegistration", true);
            if (!allowRegistration)
            {
                return Results.ValidationError("Local registration is currently disabled.");
            }

            if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(email) ||
                string.IsNullOrWhiteSpace(password))
            {
                return Results.ValidationError("All profile items are required.");
            }

            var newUser = new User
            {
                UserName = username.Trim(),
                Email = email.Trim(),
                EmailConfirmed = true
            };

            var result = await userManager.CreateAsync(newUser, password);
            if (result.Succeeded) return Results.HtmxRedirect("/");

            var errorsHtml = result.Errors.Select(e => e.Description);
            return Results.ValidationError("Error creating user.", errorsHtml);
        });

        endpoints.MapGet("/challenge/{scheme}", (string scheme, [FromQuery] string returnUrl) =>
        {
            var finalTarget = !string.IsNullOrWhiteSpace(returnUrl) ? returnUrl : "/";
            var properties = new AuthenticationProperties { RedirectUri = finalTarget };

            properties.SetString(OpenIddictClientAspNetCoreConstants.Properties.RegistrationId, scheme);

            return Results.Challenge(properties,
                authenticationSchemes: [OpenIddictClientAspNetCoreDefaults.AuthenticationScheme]);
        });

        endpoints.MapGet("/callback", async (
            HttpContext context,
            [FromServices] UserManager<User> userManager,
            [FromServices] SignInManager<User> signInManager) =>
        {
            var authResult = await context.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);

            if (!authResult.Succeeded || authResult.Principal == null)
            {
                return Results.Redirect("/login?error=handshake_failed");
            }

            var redirectTarget = authResult.Properties?.RedirectUri ?? "/";
            var providerKey = authResult.Principal.FindFirstValue(ClaimTypes.NameIdentifier)
                              ?? authResult.Principal.FindFirstValue("sub");

            var email = authResult.Principal.FindFirstValue(ClaimTypes.Email)
                        ?? authResult.Principal.FindFirstValue("email");

            var displayName = authResult.Principal.FindFirstValue(ClaimTypes.Name)
                              ?? authResult.Principal.FindFirstValue("name")
                              ?? authResult.Principal.FindFirstValue("username");

            var loginProvider =
                authResult.Properties?.GetString(OpenIddictClientAspNetCoreConstants.Properties.RegistrationId)
                ?? "ExternalProvider";

            if (!string.IsNullOrWhiteSpace(loginProvider))
            {
                loginProvider = loginProvider.ToUpper()[0] + loginProvider[1..];
            }

            if (string.IsNullOrWhiteSpace(providerKey))
            {
                return Results.Redirect("/login?error=invalid_profile_claims");
            }


            var loginResult =
                await signInManager.ExternalLoginSignInAsync(loginProvider, providerKey, isPersistent: true);
            if (loginResult.Succeeded)
            {
                return Results.Redirect(redirectTarget);
            }

            var uniqueFriendlyName = displayName?.Trim().Replace(" ", "_") ?? "external_user";

            if (await userManager.FindByNameAsync(uniqueFriendlyName) != null)
            {
                uniqueFriendlyName += $"_{providerKey[..Math.Min(4, providerKey.Length)]}";
            }

            var newUser = new User
            {
                UserName = uniqueFriendlyName,
                Email = email?.Trim(),
                EmailConfirmed = !string.IsNullOrWhiteSpace(email)
            };

            var createResult = await userManager.CreateAsync(newUser);
            if (!createResult.Succeeded)
            {
                return Results.Redirect("/login?error=account_creation_failed");
            }

            var info = new UserLoginInfo(loginProvider, providerKey, loginProvider);
            var linkResult = await userManager.AddLoginAsync(newUser, info);

            if (!linkResult.Succeeded) return Results.Redirect("/login?error=linking_failed");
            await signInManager.SignInAsync(newUser, isPersistent: true);
            return Results.Redirect(redirectTarget);
        });
    }
}