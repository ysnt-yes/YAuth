using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using YAuth.Data;

namespace YAuth.Endpoints;

public class UsersEndpoints : IEndpoint
{
    public static void RegisterRoutes(IEndpointRouteBuilder endpoints)
    {
        var mapGroup = endpoints.MapGroup("users");
        mapGroup.MapPost("/{userId}/roles",
            async ([FromServices] UserManager<User> userManager, [FromServices] RoleManager<IdentityRole> roleManager,
                [FromRoute] string userId, [FromForm] string roleId) =>
            {
                var user = await userManager.FindByIdAsync(userId);
                if (user == null) return Results.NotFound("User not found");

                var roleExists = await roleManager.RoleExistsAsync(roleId);
                if (!roleExists) return Results.BadRequest("Role not found");

                var result = await userManager.AddToRoleAsync(user, roleId);
                return result.Succeeded
                    ? Results.Ok($"User {user.UserName} added to role {roleId}.")
                    : Results.BadRequest(result.Errors);
            }).RequireAuthorization(Policies.ValidUserPolicy, Policies.AdminPolicy);
    }
}