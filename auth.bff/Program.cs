using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Azure.Storage.Blobs;
using Azure.Core;
using Azure.Security.KeyVault.Keys;
using Azure.Identity;
using auth.bff.Options;

var builder = WebApplication.CreateBuilder(args);

// Configure Azure Data Protection
var keyVaultOptions = builder.Configuration
    .GetSection("KeyVault")
    .Get<KeyVaultOptions>()!;

var azureBlobStorageOptions = builder.Configuration
    .GetSection("AzureBlobStorage")
    .Get<AzureBlobStorageOptions>()!;

builder.Services
    .AddDataProtection()
    .SetApplicationName("NotifyBFF")
    .PersistKeysToAzureBlobStorage(
        azureBlobStorageOptions.ConnectionString, 
        azureBlobStorageOptions.ContainerName, 
        azureBlobStorageOptions.BlobName)
    .ProtectKeysWithAzureKeyVault(
        new Uri(keyVaultOptions.VaultUri),
        new ClientSecretCredential(
            keyVaultOptions.TenantId,
            keyVaultOptions.ClientId,
            keyVaultOptions.ClientSecret))
    .DisableAutomaticKeyGeneration();

builder.Services.AddHttpContextAccessor();

// Configure authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.Cookie.Name = "auth.bff";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
    
    // Add expiration time for the cookie
    options.ExpireTimeSpan = TimeSpan.FromHours(1);
    // Sliding expiration means the timeout will be reset each time the user makes a request
    options.SlidingExpiration = true;
})
.AddOpenIdConnect(options =>
{
    options.Authority = builder.Configuration["Authentication:Authority"];
    options.ClientId = builder.Configuration["Authentication:ClientId"];
    options.ClientSecret = builder.Configuration["Authentication:ClientSecret"];
    options.ResponseType = "code";
    options.ResponseMode = "query";
    options.SaveTokens = true; // Store tokens in the encrypted cookie

    // Add required scopes
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.Scope.Add("offline_access"); // This scope enables refresh tokens
    options.Scope.Add("notify.api");
    options.Scope.Add("admin.api.lite");

    // Configure automatic token refresh
    options.RefreshInterval = TimeSpan.FromMinutes(5); // Buffer time before token expiry to trigger refresh
});

// Configure YARP reverse proxy
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Login endpoint
app.MapGet("/bff/login", async (HttpContext context) =>
{
    await context.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties
    {
        RedirectUri = context.Request.Headers.Referer.ToString()
    });
});

// Logout endpoint
app.MapGet("/bff/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await context.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
    return Results.Redirect("/");
});

// Configure the reverse proxy with authentication requirement for API routes
app.MapReverseProxy(proxyPipeline =>
{
    proxyPipeline.Use(async (context, next) =>
    {
        var path = context.Request.Path.ToString();
        if (path.StartsWith("/api") && !path.StartsWith("/api/public"))
        {
            if (!context.User.Identity?.IsAuthenticated ?? true)
            {
                context.Response.StatusCode = 401;
                return;
            }

            // Get the access token from the authentication ticket
            var token = await context.GetTokenAsync("access_token");
            if (!string.IsNullOrEmpty(token))
            {
                context.Request.Headers.Authorization = $"Bearer {token}";
            }
            else
            {
                Console.WriteLine("Warning: No access token available to forward to API");
            }
        }
        await next();
    });
});

app.Run();

