using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Validation.AspNetCore;

namespace YAuth.Data;

public abstract class Policies
{
    public const string ValidUserPolicy = "ValidUserPolicy";

    public static readonly Action<AuthorizationPolicyBuilder> ValidUserPolicyBuilder = policy =>
    {
        policy.AuthenticationSchemes = new List<string>
        {
            IdentityConstants.ApplicationScheme,
            OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme
        };
        policy.RequireAuthenticatedUser();
    };
    
    public const string AdminPolicy = "AdminPolicy";

    public static readonly Action<AuthorizationPolicyBuilder> AdminPolicyBuilder = policy =>
    {
        policy.RequireRole(Roles.Admin);
    };
}