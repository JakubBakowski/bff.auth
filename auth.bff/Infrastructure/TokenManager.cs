using Microsoft.Extensions.Caching.Distributed;
using System.Text.Json;

namespace auth.bff.Infrastructure;

public class TokenManager(IDistributedCache cache)
{
    private const string TokenKeyPrefix = "Tokens_";

    public async Task StoreTokens(string userId, IDictionary<string, string> tokens)
    {
        try
        {
            var key = $"{TokenKeyPrefix}{userId}";
            var tokenBytes = JsonSerializer.SerializeToUtf8Bytes(tokens);
            await cache.SetAsync(key, tokenBytes, CacheOptions.DefaultOptions);
        }
        catch (Exception ex)
        {
            // Log the error and rethrow - you might want to use proper logging here
            throw new InvalidOperationException("Failed to store tokens in cache", ex);
        }
    }

    public async Task<IDictionary<string, string>?> GetTokens(string userId)
    {
        try
        {
            var key = $"{TokenKeyPrefix}{userId}";
            var tokenBytes = await cache.GetAsync(key);
            if (tokenBytes == null) return null;
            return JsonSerializer.Deserialize<Dictionary<string, string>>(tokenBytes);
        }
        catch (Exception ex)
        {
            // Log the error and rethrow - you might want to use proper logging here
            throw new InvalidOperationException("Failed to retrieve tokens from cache", ex);
        }
    }

    public async Task<string?> GetToken(string userId, string tokenName)
    {
        var tokens = await GetTokens(userId);
        string? value;
        return tokens?.TryGetValue(tokenName, out value) == true ? value : null;
    }
} 