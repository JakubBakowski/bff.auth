using Microsoft.Extensions.Caching.Distributed;

namespace auth.bff.Infrastructure;

public static class CacheOptions
{
    public static DistributedCacheEntryOptions DefaultOptions => new()
    {
        SlidingExpiration = TimeSpan.FromHours(1),
        AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(1)
    };
} 