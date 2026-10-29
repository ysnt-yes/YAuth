using System.Security.Claims;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Polly;
using YAuth.Components.Shared;
using YAuth.Data;

namespace YAuth.Endpoints;

public class UsersEndpoints : IEndpoint
{
    public static void RegisterRoutes(IEndpointRouteBuilder endpoints)
    {
        var mapGroup = endpoints.MapGroup("users");
        mapGroup.MapPost("/{userId}/roles",
            async (
                UserManager<User> userManager,
                RoleManager<IdentityRole> roleManager,
                [FromRoute] string userId, [FromForm] string roleId) =>
            {
                var user = await userManager.FindByIdAsync(userId);
                if (user == null) return Results.NotFound("User not found");

                var roleExists = await roleManager.RoleExistsAsync(roleId);
                if (!roleExists) return Results.BadRequest("Role not found");

                var result = await userManager.AddToRoleAsync(user, roleId);
                
                if (!result.Succeeded) return Results.BadRequest(result.Errors);

                var allRoles = roleManager.Roles.Select(role => role.Name!).ToList();
                var userRoles = await userManager.GetRolesAsync(user);
                var unassignedRoles = allRoles.Where(r => !userRoles.Contains(r));
                var parameters  = UserRow.Parameters(unassignedRoles, userRoles, user.Id);
                return new RazorComponentResult<UserRow>(parameters);
            }).RequireAuthorization(Policies.ValidUserPolicy, Policies.AdminPolicy);

        mapGroup.MapDelete("/{userId}/roles",
            async (
                UserManager<User> userManager,
                RoleManager<IdentityRole> roleManager,
                HttpContext context,
                [FromRoute] string userId,
                [FromQuery] string roleId) =>
            {
                var user = await userManager.FindByIdAsync(userId);
                if (user == null) return Results.NotFound("User not found");

                var currentUserId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);

                if (user.Id == currentUserId && roleId == Roles.Admin)
                {
                    return Results.BadRequest(
                        "You are trying to self-destruct. You cannot remove admin from the current user.");
                }

                var roleExists = await roleManager.RoleExistsAsync(roleId);
                if (!roleExists) return Results.BadRequest("Role not found");

                var result = await userManager.RemoveFromRoleAsync(user, roleId);

                if (!result.Succeeded) return Results.BadRequest(result.Errors);

                var allRoles = roleManager.Roles.Select(role => role.Name!).ToList();
                var userRoles = await userManager.GetRolesAsync(user);
                var unassignedRoles = allRoles.Where(r => !userRoles.Contains(r));
                var parameters  = UserRow.Parameters(unassignedRoles, userRoles, user.Id);
                return new RazorComponentResult<UserRow>(parameters);
            }).RequireAuthorization(Policies.ValidUserPolicy, Policies.AdminPolicy);
    }
}