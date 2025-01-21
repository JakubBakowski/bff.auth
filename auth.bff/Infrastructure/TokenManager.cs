using Microsoft.Extensions.Caching.Distributed;
using System.Text.Json;

namespace auth.bff.Infrastructure;

public class TokenManager(IDistributedCache cache)
{
    private readonly IDistributedCache _cache = cache;
    private const string TokenKeyPrefix = "Tokens_";

    public async Task StoreTokens(string userId, IDictionary<string, string> tokens)
    {
        var key = $"{TokenKeyPrefix}{userId}";
        var tokenBytes = JsonSerializer.SerializeToUtf8Bytes(tokens);
        await _cache.SetAsync(key, tokenBytes, new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(1)
        });
    }

    public async Task<IDictionary<string, string>?> GetTokens(string userId)
    {
        var key = $"{TokenKeyPrefix}{userId}";
        var tokenBytes = await _cache.GetAsync(key);
        if (tokenBytes == null) return null;
        return JsonSerializer.Deserialize<Dictionary<string, string>>(tokenBytes);
    }

    public async Task<string?> GetToken(string userId, string tokenName)
    {
        var tokens = await GetTokens(userId);
        string? value;
        return tokens?.TryGetValue(tokenName, out value) == true ? value : null;
    }
} 