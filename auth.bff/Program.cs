using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using System.Security.Claims;
using auth.bff.Infrastructure;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

// Add in-memory cache for session storage
builder.Services.AddDistributedMemoryCache();
// Add Redis distributed cache
// builder.Services.AddStackExchangeRedisCache(options =>
// {
//     options.Configuration = builder.Configuration.GetConnectionString("Redis");
// });

builder.Services.AddSingleton<ITicketStore, DistributedSessionStore>();
builder.Services.AddSingleton<TokenManager>();

builder.Services.AddSession();

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
    // options.DataProtectionProvider = null; // Disable cookie encryption
    options.TicketDataFormat = new PlainTicketSerializer(); // Add custom ticket serializer

    // Add expiration time for the cookie
    options.ExpireTimeSpan = TimeSpan.FromHours(1);
    // Sliding expiration means the timeout will be reset each time the user makes a request
    options.SlidingExpiration = true;
    options.SessionStore = builder.Services.BuildServiceProvider().GetRequiredService<ITicketStore>();
})
.AddOpenIdConnect(options =>
{
    options.Authority = builder.Configuration["Authentication:Authority"];
    options.ClientId = builder.Configuration["Authentication:ClientId"];
    options.ClientSecret = builder.Configuration["Authentication:ClientSecret"];
    options.ResponseType = "code";
    options.SaveTokens = false;

     options.Events = new OpenIdConnectEvents
    {
        OnTokenValidated = async context =>
        {
            var tokenManager = context.HttpContext.RequestServices.GetRequiredService<TokenManager>();
            var userId = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            
            if (userId != null)
            {
                var tokens = new Dictionary<string, string>
                {
                    { "access_token", context.TokenEndpointResponse?.AccessToken ?? "" },
                    { "refresh_token", context.TokenEndpointResponse?.RefreshToken ?? "" },
                    { "id_token", context.TokenEndpointResponse?.IdToken ?? "" }
                };
                
                await tokenManager.StoreTokens(userId, tokens);
            }
        }
    };
    // options.UseTokenLifetime = true;  // Use token lifetime for cookie expiration
    
    // Add required scopes
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.Scope.Add("offline_access");
    options.Scope.Add("notify.api");
    options.Scope.Add("admin.api.lite");
    
});

// Configure YARP reverse proxy
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();


app.UseSession();
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
    context.Session.Clear();
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

            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (userId != null)
            {
                var tokenManager = context.RequestServices.GetRequiredService<TokenManager>();
                var token = await tokenManager.GetToken(userId, "access_token");
                
                if (!string.IsNullOrEmpty(token))
                {
                    context.Request.Headers.Authorization = $"Bearer {token}";
                }
                else
                {
                    Console.WriteLine("Warning: No access token available to forward to API");
                }
            }
        }
        await next();
    });
});

app.Run();

