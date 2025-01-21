using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Text.Json;

namespace auth.bff.Infrastructure;

// This is a simple JSON serializer for authentication tickets with Base64 encoding.
// Note: This implementation does not provide any encryption - use only in scenarios 
// where ticket security is handled by other means (e.g., encrypted communication channels)
public class PlainTicketSerializer : ISecureDataFormat<AuthenticationTicket>
{
    public string Protect(AuthenticationTicket data)
    {
        var serialized = JsonSerializer.Serialize(new
        {
            scheme = data.AuthenticationScheme,
            principal = data.Principal?.Claims.Select(c => new { c.Type, c.Value })
        });
        return Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(serialized));
    }

    public string Protect(AuthenticationTicket data, string? purpose)
    {
        return Protect(data);
    }

    public AuthenticationTicket? Unprotect(string? protectedText)
    {
        if (string.IsNullOrEmpty(protectedText))
            return null;

        try
        {
            var bytes = Convert.FromBase64String(protectedText);
            var json = System.Text.Encoding.UTF8.GetString(bytes);
            var deserialized = JsonSerializer.Deserialize<TicketData>(json);
            
            if (deserialized == null)
                return null;

            var identity = new System.Security.Claims.ClaimsIdentity(
                deserialized.principal?.Select(c => new System.Security.Claims.Claim(c.Type, c.Value)) ?? Array.Empty<System.Security.Claims.Claim>(),
                "Cookies"
            );
            
            return new AuthenticationTicket(
                new System.Security.Claims.ClaimsPrincipal(identity),
                deserialized.scheme ?? CookieAuthenticationDefaults.AuthenticationScheme
            );
        }
        catch
        {
            return null;
        }
    }

    public AuthenticationTicket? Unprotect(string? protectedText, string? purpose)
    {
        return Unprotect(protectedText);
    }

    private class TicketData
    {
        public string? scheme { get; set; }
        public ClaimData[]? principal { get; set; }
    }

    private class ClaimData
    {
        public string Type { get; set; } = "";
        public string Value { get; set; } = "";
    }
} 