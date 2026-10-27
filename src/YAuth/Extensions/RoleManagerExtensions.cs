using Microsoft.AspNetCore.Identity;

namespace YAuth.Extensions;

public static class RoleManagerExtensions
{
    public static async Task EnsureCreatedAsync(this RoleManager<IdentityRole> roleManager, string role)
    {
        if (!await roleManager.RoleExistsAsync(role))
        {
            await roleManager.CreateAsync(new IdentityRole(role));
        }
    }
    
}