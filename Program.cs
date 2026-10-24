using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using YAuth.Components;
using YAuth.Data;
using YAuth.Extensions;
using YAuth.Utils;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

builder.Services.AddRazorComponents();

builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlite(configuration.GetConnectionString("DefaultConnection"));
    options.UseOpenIddict();
});

builder.Services.AddIdentity<User, IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

var certsFolder = Path.Combine(builder.Environment.ContentRootPath, "bin/Debug/certs");
var certPassword = configuration["Certs:Password"] ?? "SuperSecretHomelabPassword123!";
var signingCertificate = CertificateManager.GetOrCreateSigningCertificate(certsFolder, certPassword);
var symmetricEncryptionKey = new SymmetricSecurityKey(
    Convert.FromBase64String("eGztWK7NMvHAqUZrczQgLKjH8oFSg0ovnknlfahXxGg="));

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<AppDbContext>();
    })
    .AddServer(options =>
    {
        options
            .SetAuthorizationEndpointUris("/connect/authorize")
            .SetTokenEndpointUris("/connect/token")
            .SetUserInfoEndpointUris("/connect/userinfo")
            .SetJsonWebKeySetEndpointUris("/connect/jwks");

        options
            .AllowAuthorizationCodeFlow()
            .AllowRefreshTokenFlow()
            .AllowClientCredentialsFlow();

        options.RegisterScopes(
            OpenIddictConstants.Scopes.OpenId,
            OpenIddictConstants.Scopes.Email,
            OpenIddictConstants.Scopes.Profile,
            "groups"
        );

        options.DisableAccessTokenEncryption();
        options.RequireProofKeyForCodeExchange();

        options.AddSigningCertificate(signingCertificate);
        options.AddEncryptionKey(symmetricEncryptionKey);
        
        options
            .UseAspNetCore()
            .DisableTransportSecurityRequirement()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough()
            .EnableUserInfoEndpointPassthrough();
    })
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

builder.Services.AddAuthentication();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(Policies.AdminPolicy, Policies.AdminPolicyBuilder);
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();


app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>();

app.MapYAuthEndpoints();

await using (var scope = app.Services.CreateAsyncScope())
{
    var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await context.Database.EnsureCreatedAsync();

    var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
    if (await manager.FindByClientIdAsync("service-worker") is null)
    {
        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            DisplayName = "Service Worker",
            ClientId = "service-worker",
            ClientSecret = "388D45FA-B36B-4988-BA59-B187D329C207",
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials
            }
        });
    }
}

app.Run();