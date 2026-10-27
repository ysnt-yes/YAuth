using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Client;
using OpenIddict.EntityFrameworkCore.Models;
using YAuth.Components;
using YAuth.Data;
using YAuth.Extensions;
using YAuth.Utils;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

var contentRootPath = builder.Environment.ContentRootPath;
var storagePath = Path.Combine(contentRootPath, "storage");

builder.Services.AddRazorComponents();
builder.Services.AddCascadingAuthenticationState();

builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseSqlite(configuration.GetConnectionString("DefaultConnection") ?? $"Data Source={storagePath}/yauth.db");
    options.UseOpenIddict();
});

builder.Services.AddAuthentication(IdentityConstants.ApplicationScheme)
    .AddCookie(IdentityConstants.ApplicationScheme, options =>
    {
        options.AccessDeniedPath = new PathString("/forbidden");
        options.LoginPath = new PathString("/login");
        options.LogoutPath = new PathString("/logout");

        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.Redirect(context.Options.AccessDeniedPath);
            return Task.CompletedTask;
        };
    })
    .AddCookie(IdentityConstants.ExternalScheme);

builder.Services.AddIdentityCore<User>(options => { options.Stores.SchemaVersion = IdentitySchemaVersions.Version3; })
    .AddRoles<IdentityRole>()
    .AddEntityFrameworkStores<AppDbContext>()
    .AddSignInManager()
    .AddDefaultTokenProviders();

var certsFolder = Path.Combine(storagePath, "certs");
var certPassword = configuration["Crypto:CertPassword"];
var signingCertificate = CertificateManager.GetOrCreateSigningCertificate(certsFolder,
    certPassword ?? throw new InvalidOperationException("Cert Password is NOT SET. Set `Certs__Password` in ENV."));
var symmetricEncryptionKey = new SymmetricSecurityKey(
    Convert.FromBase64String(configuration["Crypto:EncryptionKey"] ??
                             throw new InvalidOperationException("Encryption Key is NOT SET!")));

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<AppDbContext>();

        options
            .ReplaceApplicationManager<OpenIddictEntityFrameworkCoreApplication,
                PlainTextApplicationManager<OpenIddictEntityFrameworkCoreApplication>>();
    })
    .AddServer(options =>
    {
        options
            .SetAuthorizationEndpointUris("/oidc/connect/authorize")
            .SetTokenEndpointUris("/oidc/connect/token")
            .SetUserInfoEndpointUris("/oidc/connect/userinfo")
            .SetJsonWebKeySetEndpointUris("/oidc/connect/jwks");

        options
            .AllowAuthorizationCodeFlow()
            .AllowRefreshTokenFlow()
            .AllowClientCredentialsFlow();

        options.RegisterScopes(
            OpenIddictConstants.Scopes.OpenId,
            OpenIddictConstants.Scopes.Email,
            OpenIddictConstants.Scopes.Profile,
            OpenIddictConstants.Scopes.Roles
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
    })
    .AddClient(options =>
    {
        options.AllowAuthorizationCodeFlow();

        options.UseAspNetCore()
            .DisableTransportSecurityRequirement()
            .EnableRedirectionEndpointPassthrough()
            .EnablePostLogoutRedirectionEndpointPassthrough();

        options.AddSigningCertificate(signingCertificate);
        options.AddEncryptionKey(symmetricEncryptionKey);

        var externalAuthProviders =
            configuration.GetSection("Authentication:Providers").Get<List<ExternalAuthProvider>>() ?? [];

        var webProviders = options.UseWebProviders();

        foreach (var p in externalAuthProviders)
        {
            if (string.Equals(p.Type, "Discord", StringComparison.OrdinalIgnoreCase))
            {
                webProviders.AddDiscord(discord =>
                {
                    discord.SetClientId(p.ClientId)
                        .SetProviderDisplayName("Discord")
                        .SetRegistrationId("discord")
                        .SetClientSecret(p.ClientSecret)
                        .AddScopes("identify", "email")
                        .SetRedirectUri("/auth/callback");
                });
            }
            if (string.Equals(p.Type, "Custom", StringComparison.OrdinalIgnoreCase))
            {
                options.AddRegistration(new OpenIddictClientRegistration
                {
                    Issuer = new Uri(p.Authority ?? throw new Exception("Missing OIDC Issuer")),
                    ClientId = p.ClientId,
                    ClientSecret = p.ClientSecret,
                    RedirectUri = new Uri($"/signin-oidc-{p.Id}", UriKind.Relative)
                });
            }
        }
    });

builder.Services.AddAuthorizationBuilder()
    .AddPolicy(Policies.AdminPolicy, Policies.AdminPolicyBuilder)
    .AddPolicy(Policies.ValidUserPolicy, Policies.ValidUserPolicyBuilder);

var cookiePolicy = builder.Environment.IsDevelopment() ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;

builder.Services.Configure<CookieAuthenticationOptions>(IdentityConstants.ExternalScheme, options =>
{
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = cookiePolicy;
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");

    var forwardedOptions = new ForwardedHeadersOptions
    {
        ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
    };
    forwardedOptions.KnownIPNetworks.Clear();
    forwardedOptions.KnownProxies.Clear();
    app.UseForwardedHeaders(forwardedOptions);
}
else
{
    app.UseDeveloperExceptionPage();
}

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>();

app.MapYAuthEndpoints();

using (var scope = app.Services.CreateScope())
{
    await scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.MigrateAsync();
}

app.Run();