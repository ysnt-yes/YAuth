using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using YAuth.Data;
using YAuth.Extensions;
using YAuth.Utils;

namespace YAuth.Endpoints;

public class SetupModel
{
    [Required(ErrorMessage = "Username is required.")]
    public string Username { get; set; } = string.Empty;

    [Required(ErrorMessage = "Email is required.")]
    [EmailAddress(ErrorMessage = "Invalid email format.")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required.")]
    public string Password { get; set; } = string.Empty;

    public void Deconstruct(out string username, out string email, out string password)
    {
        username = Username;
        email = Email;
        password = Password;
    }
}

public class ApiEndpoints : IEndpoint
{
    public static void RegisterRoutes(IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost("/setup/initialize", async (
            [FromForm] SetupModel model,
            [FromServices] UserManager<User> userManager,
            [FromServices] RoleManager<IdentityRole> roleManager) =>
        {
            var (username, email, password) = model;
            if (await userManager.Users.AnyAsync())
            {
                return Results.ValidationError("Setup has already been completed.");
            }

            if (string.IsNullOrWhiteSpace(username) || 
                string.IsNullOrWhiteSpace(email) ||
                string.IsNullOrWhiteSpace(password))
            {
                return Results.ValidationError("All registration fields are required.");
            }

            await roleManager.EnsureCreatedAsync(Roles.Admin);

            var adminUser = new User
            {
                UserName = username.Trim(),
                Email = email.Trim(),
                EmailConfirmed = true
            };

            var result = await userManager.CreateAsync(adminUser, password);
            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description).ToList();

                return Results.ValidationError("Invalid Admin Credentials", errors);
            }

            await userManager.AddToRoleAsync(adminUser, "admin");
            return Results.HtmxRedirect("/login");
        });
    }
}