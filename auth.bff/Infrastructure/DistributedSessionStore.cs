using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Caching.Distributed;
using System.Text.Json;

namespace auth.bff.Infrastructure;

public class DistributedSessionStore(IDistributedCache cache) : ITicketStore
{
    private const string KeyPrefix = "AuthSessionStore-";
    private readonly IDistributedCache _cache = cache ?? throw new ArgumentNullException(nameof(cache));
    private readonly TicketSerializer _ticketSerializer = new();

    public async Task<string> StoreAsync(AuthenticationTicket ticket)
    {
        Console.WriteLine("Starting StoreAsync for authentication ticket");
        
        var userId = ticket.Principal?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        Console.WriteLine($"Found user ID from claims: {userId ?? "null"}");
        
        string key;
        if (string.IsNullOrEmpty(userId))
        {
            var guid = Guid.NewGuid();
            Console.WriteLine($"Warning: User ID not found in authentication ticket. Using generated GUID {guid} instead.");
            key = $"{KeyPrefix}{guid}";
        }
        else
        {
            key = $"{KeyPrefix}{userId}";
            Console.WriteLine($"Using user ID to generate key: {key}");
        }

        Console.WriteLine($"Calling RenewAsync with key: {key}");
        await RenewAsync(key, ticket);
        
        Console.WriteLine($"Successfully stored authentication ticket with key: {key}");
        return key;
    }

    public Task RenewAsync(string key, AuthenticationTicket ticket)
    {
        if (ticket == null) throw new ArgumentNullException(nameof(ticket));

        var options = new DistributedCacheEntryOptions();
        var expiresUtc = ticket.Properties.ExpiresUtc;
        if (expiresUtc.HasValue)
        {
            options.SetAbsoluteExpiration(expiresUtc.Value);
        }

        byte[] val = _ticketSerializer.Serialize(ticket);
        return _cache.SetAsync(key, val, options);
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        var bytes = await _cache.GetAsync(key);
        if (bytes == null) return null;
        var ticket = _ticketSerializer.Deserialize(bytes);

        return _ticketSerializer.Deserialize(bytes);
    }

    public Task RemoveAsync(string key)
    {
        return _cache.RemoveAsync(key);
    }
} 