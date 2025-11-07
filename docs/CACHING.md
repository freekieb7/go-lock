# Caching Implementation Guide

This document describes the comprehensive multi-layer caching system implemented for the go-lock OAuth service.

## Architecture Overview

The caching system provides multiple layers of caching to improve performance and reduce database load:

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Session   │  │    JWKS     │  │  Response   │         │
│  │   Cache     │  │   Cache     │  │   Cache     │         │
│  └─────────────┘  └─────────────┘  └─────────────┘         │
├─────────────────────────────────────────────────────────────┤
│                 Cache Manager Layer                         │
│  ┌─────────────┐                    ┌─────────────┐         │
│  │ In-Memory   │                    │   Redis     │         │
│  │   Cache     │                    │   Cache     │         │
│  │  (L1 Fast)  │                    │ (L2 Shared) │         │
│  └─────────────┘                    └─────────────┘         │
├─────────────────────────────────────────────────────────────┤
│                     Storage Layer                           │
│              PostgreSQL Database                            │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. Redis Cache Service (`internal/cache/redis.go`)

The core Redis integration providing:
- **Key-value operations**: Set, Get, Delete with TTL support
- **Atomic operations**: SetNX, Increment for counters and locks
- **Pattern operations**: Bulk delete with wildcards
- **GetOrSet**: Cache-aside pattern with automatic fallback
- **Health monitoring**: Connection health and statistics
- **Graceful degradation**: NoOp client when Redis unavailable

#### Configuration
```go
type Config struct {
    Enabled      bool          // Enable/disable Redis
    Addr         string        // Redis server address
    Password     string        // Redis password  
    DB           int           // Redis database number
    PoolSize     int           // Connection pool size
    MinIdleConns int           // Minimum idle connections
    MaxRetries   int           // Maximum retry attempts
    Prefix       string        // Key prefix for namespacing
}
```

### 2. Session Store Cache (`internal/cache/session_store.go`)

Wraps the existing session store with Redis caching:
- **Read-through caching**: Automatic cache population on miss
- **Write-through caching**: Cache updates on session save
- **Cache invalidation**: Automatic cleanup on session delete
- **Security**: Token masking in logs for security

#### Usage
```go
// Wrap existing session store with caching
cachedStore := cache.NewSessionStore(redisService, baseStore, logger, config)

// Use exactly like the original store
session, err := cachedStore.GetSessionByToken(ctx, token)
```

### 3. JWKS Cache (`internal/cache/jwks_cache.go`)

Specialized caching for JSON Web Key Sets:
- **Long TTL**: 24-hour default for stable key sets
- **Cache-aside pattern**: Generate on miss, cache on success  
- **Key rotation support**: Easy invalidation when keys change
- **Issuer-specific**: Separate cache per OAuth issuer

#### Usage
```go
jwksCache := cache.NewJWKSCache(redisService, logger)

jwks, err := jwksCache.GetJWKS(ctx, issuer, func() (*jwks.JWKSet, error) {
    return generateFreshJWKS(issuer)
})
```

### 4. Cache Manager (`internal/cache/manager.go`)

Unified interface managing all caching concerns:
- **Multi-layer**: In-memory L1 + Redis L2 caching
- **Domain-specific**: Client, User, Permission caches with appropriate TTLs
- **Background cleanup**: Automatic expired entry eviction
- **Health monitoring**: Combined health status for all cache layers
- **Statistics**: Performance metrics and cache hit rates

#### Features
- **In-memory cache**: Ultra-fast L1 cache for frequently accessed data
- **Automatic eviction**: LRU-style cleanup of expired entries
- **Graceful degradation**: Works without Redis, memory-only mode
- **Invalidation patterns**: Bulk invalidation by user, client, etc.

### 5. HTTP Response Caching (`internal/web/middleware/redis_cache.go`)

Middleware for caching HTTP responses:
- **Selective caching**: Configurable paths and status codes
- **Vary header support**: Cache different responses based on headers
- **Cache invalidation**: Automatic cleanup on mutations
- **Hit/Miss headers**: X-Cache headers for debugging

#### Configuration
```go
config := middleware.RedisCacheConfig{
    Cache:      redisService,
    DefaultTTL: 5 * time.Minute,
    VaryHeaders: []string{"Authorization", "Accept"},
    CacheablePaths: []string{"/api/clients", "/oauth/jwks"},
    ExcludePaths: []string{"/oauth/authorize", "/oauth/token"},
}
```

## Configuration

### Environment Variables

Add to your `.env` file:

```bash
# Cache Configuration
CACHE_ENABLED=true
REDIS_ADDR=localhost:6379
REDIS_PASSWORD=
REDIS_DB=0
REDIS_POOL_SIZE=10
CACHE_DEFAULT_TTL=5m
CACHE_SESSION_TTL=30m
CACHE_JWKS_TTL=24h
```

### Application Config

```go
type Cache struct {
    Enabled      bool
    RedisAddr    string
    RedisPassword string
    RedisDB      int
    RedisPoolSize int
    DefaultTTL   time.Duration
    SessionTTL   time.Duration
    JWKSTTL      time.Duration
}
```

## Integration Guide

### 1. Initialize Cache Manager

```go
func main() {
    cfg := config.Load()
    logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
    
    // Setup cache manager
    cacheManager, err := cache.NewManager(&cache.ManagerConfig{
        RedisConfig: &cache.Config{
            Enabled:  cfg.Cache.Enabled,
            Addr:     cfg.Cache.RedisAddr,
            Password: cfg.Cache.RedisPassword,
            DB:       cfg.Cache.RedisDB,
            Prefix:   "golock:",
        },
        DefaultTTL: cfg.Cache.DefaultTTL,
    }, logger)
    
    defer cacheManager.Close()
}
```

### 2. Add Middleware

```go
// Add caching middleware to your HTTP stack
middlewares := []func(http.Handler) http.Handler{
    // ... other middleware
    middleware.APIResponseCacheMiddleware(cacheManager.Redis(), logger),
    middleware.StaticResourceCacheMiddleware(cacheManager.Redis(), logger),
    middleware.CacheInvalidationMiddleware(cacheManager.Redis(), logger),
}
```

### 3. Service Integration

```go
type ClientService struct {
    cache *cache.Manager
    // ... other dependencies
}

func (s *ClientService) GetClient(ctx context.Context, clientID string) (*Client, error) {
    // Try cache first
    var client Client
    if err := s.cache.GetCachedClient(ctx, clientID, &client); err == nil {
        return &client, nil
    }
    
    // Cache miss - get from database
    client, err := s.getFromDatabase(ctx, clientID)
    if err != nil {
        return nil, err
    }
    
    // Cache for next time
    go s.cache.CacheClient(context.Background(), clientID, client)
    return &client, nil
}
```

## Cache Patterns

### 1. Cache-Aside (Lazy Loading)
```go
// Read pattern
if err := cache.Get(key, &result); err == cache.ErrCacheMiss {
    result = loadFromDatabase()
    cache.Set(key, result, ttl)
}

// Write pattern  
updateDatabase(data)
cache.Delete(key) // Invalidate
```

### 2. Write-Through
```go
// Update both cache and database
err := updateDatabase(data)
if err == nil {
    cache.Set(key, data, ttl)
}
```

### 3. Cache-First (GetOrSet)
```go
cache.GetOrSet(key, &result, ttl, func() (interface{}, error) {
    return loadFromDatabase(), nil
})
```

## Performance Considerations

### Cache Key Design
- **Hierarchical**: Use colons for namespacing (`user:123`, `client:abc`)
- **Consistent**: Same format across the application
- **Informative**: Include enough context for debugging

### TTL Strategy
- **Static content**: Long TTL (hours/days)
- **User data**: Medium TTL (minutes)  
- **Session data**: Short TTL with refresh
- **Permissions**: Very short TTL for security

### Memory Management
- **In-memory limits**: Configure max entries to prevent OOM
- **Background cleanup**: Regular expired entry removal
- **Graceful degradation**: Function without cache if needed

## Monitoring

### Health Checks
```go
health := cacheManager.Health(ctx)
// Returns map with Redis and in-memory cache status
```

### Statistics
```go
stats := cacheManager.Stats(ctx)
// Returns hit/miss rates, connection pools, memory usage
```

### Logging
- Cache hits/misses logged at debug level
- Cache errors logged at warn level
- Performance metrics available

## Testing

### Unit Tests
```bash
# Run tests without Redis
go test ./internal/cache/...

# Run tests with Redis
REDIS_TESTS=true go test ./internal/cache/...
```

### Benchmarks
```bash
# Benchmark cache performance
REDIS_TESTS=true go test -bench=. ./internal/cache/...
```

### Load Testing
Use the provided Docker Compose with Redis:
```bash
docker-compose up redis
REDIS_TESTS=true go test -bench=. -benchmem ./internal/cache/...
```

## Best Practices

### 1. Error Handling
- **Graceful degradation**: Always work without cache
- **Fire-and-forget**: Don't block on cache errors
- **Timeouts**: Use context with timeouts for cache operations

### 2. Security
- **Key namespacing**: Prevent key collisions
- **Data sensitivity**: Don't cache sensitive data without encryption  
- **Access control**: Redis auth and network security

### 3. Observability
- **Structured logging**: Include cache keys and operations
- **Metrics**: Track hit rates, latencies, error rates
- **Alerting**: Monitor Redis health and memory usage

### 4. Cache Invalidation
- **Targeted**: Invalidate specific keys when possible
- **Pattern-based**: Use wildcards for related data
- **Time-based**: Let TTL handle most invalidation

## Troubleshooting

### Common Issues

1. **Redis Connection Failed**
   - Check Redis server is running
   - Verify network connectivity and credentials
   - Application will use NoOp client automatically

2. **Cache Misses**
   - Check TTL configuration
   - Verify key naming consistency
   - Monitor for premature eviction

3. **Memory Usage**
   - Monitor in-memory cache size
   - Adjust cleanup intervals
   - Check for memory leaks

4. **Performance Issues**
   - Profile cache operations
   - Check Redis connection pool size
   - Monitor network latency

### Debug Mode
Enable debug logging to see cache operations:
```go
logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug,
}))
```

## Migration Guide

### From No Caching
1. Add cache configuration to environment
2. Initialize cache manager in main()
3. Gradually add caching to services
4. Monitor performance improvements

### Cache Warming
```go
// Pre-populate cache with frequently accessed data
go func() {
    clients := getAllActiveClients()
    for _, client := range clients {
        cacheManager.CacheClient(ctx, client.ID, client)
    }
}()
```

This caching implementation provides a solid foundation for high-performance OAuth services with multiple cache layers, comprehensive monitoring, and production-ready features.