using Microsoft.AspNetCore.Authorization;

namespace YAuth.Data;

public abstract class Policies
{
    public const string AdminPolicy = "AdminPolicy";

    public static readonly Action<AuthorizationPolicyBuilder> AdminPolicyBuilder = policy =>
    {
        policy.RequireRole("admin");
    };
}