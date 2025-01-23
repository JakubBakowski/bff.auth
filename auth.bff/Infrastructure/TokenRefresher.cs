using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System.Net.Http.Json;
using System.Text.Json;

namespace auth.bff.Infrastructure;

public static class TokenRefresher
{
    private static readonly SemaphoreSlim TokenRefreshSemaphore = new(1, 1); //lock on redis

    public static async Task RefreshTokenIfNeeded(CookieValidatePrincipalContext context, IConfiguration configuration)
    {
        var userId = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            context.RejectPrincipal();
            return;
        }

        var tokenManager = context.HttpContext.RequestServices.GetRequiredService<TokenManager>();
        var tokens = await tokenManager.GetTokens(userId);
        
        if (tokens == null || !tokens.TryGetValue("access_token", out var accessToken) || string.IsNullOrEmpty(accessToken))
        {
            context.RejectPrincipal();
            return;
        }

        var handler = new JwtSecurityTokenHandler();
        var jwtToken = handler.ReadJwtToken(accessToken);

        // Only refresh if token expires in less than 5 minutes
        if (jwtToken.ValidTo > DateTime.UtcNow.AddMinutes(59))
        {
            return;
        }

        // Try to acquire refresh lock
        if (!await TokenRefreshSemaphore.WaitAsync(TimeSpan.FromSeconds(5)))
        {
            // If we can't acquire the lock quickly, just continue with the current token
            return;
        }

        try
        {
            // Double-check token expiration after acquiring lock
            tokens = await tokenManager.GetTokens(userId);
            if (tokens == null || !tokens.TryGetValue("access_token", out accessToken) || string.IsNullOrEmpty(accessToken))
            {
                context.RejectPrincipal();
                return;
            }

            jwtToken = handler.ReadJwtToken(accessToken);
            if (jwtToken.ValidTo > DateTime.UtcNow.AddMinutes(59))
            {
                return;
            }

            if (!tokens.TryGetValue("refresh_token", out var refreshToken) || string.IsNullOrEmpty(refreshToken))
            {
                context.RejectPrincipal();
                return;
            }

            var authority = configuration["Authentication:Authority"]?.TrimEnd('/');
            var clientId = configuration["Authentication:ClientId"];
            var clientSecret = configuration["Authentication:ClientSecret"];

            if (string.IsNullOrEmpty(authority) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
            {
                throw new InvalidOperationException("Missing required authentication configuration");
            }

            using var client = new HttpClient();
            var response = await client.PostAsync(
                $"{authority}/connect/token",
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "refresh_token",
                    ["client_id"] = clientId,
                    ["client_secret"] = clientSecret,
                    ["refresh_token"] = refreshToken,
                }));

            if (!response.IsSuccessStatusCode)
            {
                var error = await response.Content.ReadAsStringAsync();
                Console.WriteLine($"Token refresh failed. Status: {response.StatusCode}. Error: {error}");
                
                if (error.Contains("invalid_grant"))
                {
                    await tokenManager.RemoveTokens(userId);
                }
                
                context.RejectPrincipal();
                return;
            }

            var result = await response.Content.ReadFromJsonAsync<Dictionary<string, JsonElement>>();
            if (result == null)
            {
                context.RejectPrincipal();
                return;
            }

            var newTokens = new Dictionary<string, string>();
            foreach (var (key, value) in result)
            {
                newTokens[key] = value.ValueKind switch
                {
                    JsonValueKind.String => value.GetString() ?? string.Empty,
                    JsonValueKind.Number => value.ToString(),
                    _ => value.ToString()
                };
            }

            await tokenManager.StoreTokens(userId, newTokens);
            Console.WriteLine("Successfully refreshed tokens");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Token refresh failed: {ex.Message}");
            context.RejectPrincipal();
        }
        finally
        {
            TokenRefreshSemaphore.Release();
        }
    }
} 