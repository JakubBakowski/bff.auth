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

        var options = new DistributedCacheEntryOptions
        {
            SlidingExpiration = TimeSpan.FromHours(1),
            AbsoluteExpirationRelativeToNow=  TimeSpan.FromDays(1)
        };

        try
        {
            byte[] val = _ticketSerializer.Serialize(ticket);
            return _cache.SetAsync(key, val, options);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Failed to serialize or store authentication ticket", ex);
        }
    }

    public async Task<AuthenticationTicket?> RetrieveAsync(string key)
    {
        try
        {
            var bytes = await _cache.GetAsync(key);
            if (bytes == null) return null;
            return _ticketSerializer.Deserialize(bytes);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Failed to retrieve or deserialize authentication ticket", ex);
        }
    }

    public Task RemoveAsync(string key)
    {
        return _cache.RemoveAsync(key);
    }
} 