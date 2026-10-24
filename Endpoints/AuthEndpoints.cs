using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using YAuth.Data;
using YAuth.Utils;

namespace YAuth.Endpoints;

public abstract class AuthEndpoints : IEndpoint
{
    public static void RegisterRoutes(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/login", async (
            [FromForm] string username,
            [FromForm] string password,
            [FromQuery] string? returnUrl,
            SignInManager<User> signInManager) =>
        {
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

        endpoints.MapPost("/register", async (
            [FromForm] string username,
            [FromForm] string email,
            [FromForm] string password,
            UserManager<User> userManager) =>
        {
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
    }
}