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
        var userId = ticket.Principal?.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        string key;
        if (string.IsNullOrEmpty(userId))
        {
            var guid = Guid.NewGuid();
            key = $"{KeyPrefix}{guid}";
        }
        else
        {
            key = $"{KeyPrefix}{userId}";
        }

        await RenewAsync(key, ticket);
        
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
        return ticket;
    }

    public Task RemoveAsync(string key)
    {
        return _cache.RemoveAsync(key);
    }
} 