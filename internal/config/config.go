package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

type Environment string

const (
	EnvDevelopment Environment = "development"
	EnvProduction  Environment = "production"
	EnvTesting     Environment = "testing"
)

func (e Environment) IsValid() bool {
	switch e {
	case EnvDevelopment, EnvProduction, EnvTesting:
		return true
	}
	return false
}

type Config struct {
	Server    Server
	Database  Database
	Security  Security
	RateLimit RateLimit
	Cache     Cache
	BaseURL   string
}

type Server struct {
	Port           int
	Environment    Environment
	WriteTimeout   time.Duration
	ReadTimeout    time.Duration
	IdleTimeout    time.Duration
	MaxHeaderBytes int
}

func (s Server) IsProduction() bool {
	return s.Environment == EnvProduction
}

// GetBaseURL returns the configured base URL or constructs one from server config
func (c Config) GetBaseURL() string {
	if c.BaseURL != "" {
		return c.BaseURL
	}

	// Fallback to localhost for development
	scheme := "http"
	if c.Server.IsProduction() {
		scheme = "https"
	}
	return fmt.Sprintf("%s://localhost:%d", scheme, c.Server.Port)
}

type Database struct {
	URL             string
	MaxOpenConns    int32
	MaxIdleConns    int32
	ConnMaxLifetime time.Duration
	ConnMaxIdleTime time.Duration
}

type Security struct {
	APIKey                string
	EnableHSTS            bool
	HSTSMaxAge            int
	HSTSIncludeSubdomains bool
	ContentSecurityPolicy string
	ReferrerPolicy        string
	PermissionsPolicy     string
}

type RateLimit struct {
	Enabled        bool
	OAuthRequests  int
	APIRequests    int
	PublicRequests int
	AdminRequests  int
	WindowDuration time.Duration
}

type Cache struct {
	Enabled       bool
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	RedisPoolSize int
	DefaultTTL    time.Duration
	SessionTTL    time.Duration
	JWKSTTL       time.Duration
}

// New creates a new configuration with safe error handling
func New() Config {
	config, err := Load()
	if err != nil {
		// For backward compatibility, log and exit, but this should be handled by caller
		log.Fatalf("Failed to load configuration: %v", err)
	}
	return config
}

// Load loads configuration with proper error handling (recommended)
func Load() (Config, error) {
	var config Config
	var err error

	// Server configuration
	config.Server.Port, err = getEnvIntSafe("SERVER_PORT", 8080, false)
	if err != nil {
		return config, fmt.Errorf("server port config error: %w", err)
	}

	config.Server.Environment, err = getEnvEnvironmentSafe("SERVER_ENVIRONMENT", EnvDevelopment, false)
	if err != nil {
		return config, fmt.Errorf("server environment config error: %w", err)
	}

	config.Server.WriteTimeout, err = getEnvDurationSafe("SERVER_WRITE_TIMEOUT", 15*time.Second, false)
	if err != nil {
		return config, fmt.Errorf("server write timeout config error: %w", err)
	}

	config.Server.ReadTimeout, err = getEnvDurationSafe("SERVER_READ_TIMEOUT", 15*time.Second, false)
	if err != nil {
		return config, fmt.Errorf("server read timeout config error: %w", err)
	}

	config.Server.IdleTimeout, err = getEnvDurationSafe("SERVER_IDLE_TIMEOUT", 60*time.Second, false)
	if err != nil {
		return config, fmt.Errorf("server idle timeout config error: %w", err)
	}

	config.Server.MaxHeaderBytes, err = getEnvIntSafe("SERVER_MAX_HEADER_BYTES", 1<<20, false)
	if err != nil {
		return config, fmt.Errorf("server max header bytes config error: %w", err)
	}

	// Database configuration
	config.Database.URL, err = getEnvStringSafe("DB_URL", "", true)
	if err != nil {
		return config, fmt.Errorf("database URL config error: %w", err)
	}

	config.Database.MaxOpenConns, err = getEnvInt32Safe("DB_MAX_OPEN_CONNS", 25, false)
	if err != nil {
		return config, fmt.Errorf("database max open conns config error: %w", err)
	}

	config.Database.MaxIdleConns, err = getEnvInt32Safe("DB_MAX_IDLE_CONNS", 5, false)
	if err != nil {
		return config, fmt.Errorf("database max idle conns config error: %w", err)
	}

	config.Database.ConnMaxLifetime, err = getEnvDurationSafe("DB_CONN_MAX_LIFETIME", 5*time.Minute, false)
	if err != nil {
		return config, fmt.Errorf("database conn max lifetime config error: %w", err)
	}

	config.Database.ConnMaxIdleTime, err = getEnvDurationSafe("DB_CONN_MAX_IDLE_TIME", 5*time.Minute, false)
	if err != nil {
		return config, fmt.Errorf("database conn max idle time config error: %w", err)
	}

	// Security configuration
	config.Security.APIKey, err = getEnvStringSafe("API_KEY", "", false)
	if err != nil {
		return config, fmt.Errorf("API key config error: %w", err)
	}

	config.Security.EnableHSTS, err = getEnvBoolSafe("SECURITY_ENABLE_HSTS", true, false)
	if err != nil {
		return config, fmt.Errorf("HSTS enable config error: %w", err)
	}

	config.Security.HSTSMaxAge, err = getEnvIntSafe("SECURITY_HSTS_MAX_AGE", 31536000, false)
	if err != nil {
		return config, fmt.Errorf("HSTS max age config error: %w", err)
	}

	config.Security.HSTSIncludeSubdomains, err = getEnvBoolSafe("SECURITY_HSTS_INCLUDE_SUBDOMAINS", true, false)
	if err != nil {
		return config, fmt.Errorf("HSTS include subdomains config error: %w", err)
	}

	config.Security.ContentSecurityPolicy, err = getEnvStringSafe("SECURITY_CSP", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'", false)
	if err != nil {
		return config, fmt.Errorf("CSP config error: %w", err)
	}

	config.Security.ReferrerPolicy, err = getEnvStringSafe("SECURITY_REFERRER_POLICY", "strict-origin-when-cross-origin", false)
	if err != nil {
		return config, fmt.Errorf("referrer policy config error: %w", err)
	}

	config.Security.PermissionsPolicy, err = getEnvStringSafe("SECURITY_PERMISSIONS_POLICY", "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()", false)
	if err != nil {
		return config, fmt.Errorf("permissions policy config error: %w", err)
	}

	// Rate limit configuration
	config.RateLimit.Enabled, err = getEnvBoolSafe("RATE_LIMIT_ENABLED", true, false)
	if err != nil {
		return config, fmt.Errorf("rate limit enabled config error: %w", err)
	}

	config.RateLimit.OAuthRequests, err = getEnvIntSafe("RATE_LIMIT_OAUTH_REQUESTS", 10, false)
	if err != nil {
		return config, fmt.Errorf("rate limit OAuth requests config error: %w", err)
	}

	config.RateLimit.APIRequests, err = getEnvIntSafe("RATE_LIMIT_API_REQUESTS", 100, false)
	if err != nil {
		return config, fmt.Errorf("rate limit API requests config error: %w", err)
	}

	config.RateLimit.PublicRequests, err = getEnvIntSafe("RATE_LIMIT_PUBLIC_REQUESTS", 60, false)
	if err != nil {
		return config, fmt.Errorf("rate limit public requests config error: %w", err)
	}

	config.RateLimit.AdminRequests, err = getEnvIntSafe("RATE_LIMIT_ADMIN_REQUESTS", 5, false)
	if err != nil {
		return config, fmt.Errorf("rate limit admin requests config error: %w", err)
	}

	config.RateLimit.WindowDuration, err = getEnvDurationSafe("RATE_LIMIT_WINDOW_DURATION", time.Minute, false)
	if err != nil {
		return config, fmt.Errorf("rate limit window duration config error: %w", err)
	}

	config.BaseURL, err = getEnvStringSafe("BASE_URL", "", false)
	if err != nil {
		return config, fmt.Errorf("base URL config error: %w", err)
	}

	// Cache configuration
	config.Cache.Enabled, err = getEnvBoolSafe("CACHE_ENABLED", true, false)
	if err != nil {
		return config, fmt.Errorf("cache enabled config error: %w", err)
	}

	config.Cache.RedisAddr, err = getEnvStringSafe("REDIS_ADDR", "localhost:6379", false)
	if err != nil {
		return config, fmt.Errorf("Redis address config error: %w", err)
	}

	config.Cache.RedisPassword, err = getEnvStringSafe("REDIS_PASSWORD", "", false)
	if err != nil {
		return config, fmt.Errorf("Redis password config error: %w", err)
	}

	config.Cache.RedisDB, err = getEnvIntSafe("REDIS_DB", 0, false)
	if err != nil {
		return config, fmt.Errorf("Redis DB config error: %w", err)
	}

	config.Cache.RedisPoolSize, err = getEnvIntSafe("REDIS_POOL_SIZE", 10, false)
	if err != nil {
		return config, fmt.Errorf("Redis pool size config error: %w", err)
	}

	config.Cache.DefaultTTL, err = getEnvDurationSafe("CACHE_DEFAULT_TTL", 5*time.Minute, false)
	if err != nil {
		return config, fmt.Errorf("cache default TTL config error: %w", err)
	}

	config.Cache.SessionTTL, err = getEnvDurationSafe("CACHE_SESSION_TTL", 30*time.Minute, false)
	if err != nil {
		return config, fmt.Errorf("cache session TTL config error: %w", err)
	}

	config.Cache.JWKSTTL, err = getEnvDurationSafe("CACHE_JWKS_TTL", 24*time.Hour, false)
	if err != nil {
		return config, fmt.Errorf("cache JWKS TTL config error: %w", err)
	}

	return config, nil
}

// Safe versions of config helpers that return errors instead of using log.Fatal

func getEnvStringSafe(key, defaultValue string, required bool) (string, error) {
	value, exists := os.LookupEnv(key)
	if !exists {
		if required {
			return "", fmt.Errorf("environment variable %s is required", key)
		}
		return defaultValue, nil
	}
	return value, nil
}

func getEnvIntSafe(key string, defaultValue int, required bool) (int, error) {
	valueStr, exists := os.LookupEnv(key)
	if !exists {
		if required {
			return 0, fmt.Errorf("environment variable %s is required", key)
		}
		return defaultValue, nil
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return 0, fmt.Errorf("environment variable %s must be an integer: %w", key, err)
	}
	return value, nil
}

func getEnvInt32Safe(key string, defaultValue int32, required bool) (int32, error) {
	valueStr, exists := os.LookupEnv(key)
	if !exists {
		if required {
			return 0, fmt.Errorf("environment variable %s is required", key)
		}
		return defaultValue, nil
	}
	value, err := strconv.ParseInt(valueStr, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("environment variable %s must be an integer: %w", key, err)
	}
	return int32(value), nil
}

func getEnvDurationSafe(key string, defaultValue time.Duration, required bool) (time.Duration, error) {
	valueStr, exists := os.LookupEnv(key)
	if !exists {
		if required {
			return 0, fmt.Errorf("environment variable %s is required", key)
		}
		return defaultValue, nil
	}
	value, err := time.ParseDuration(valueStr)
	if err != nil {
		return 0, fmt.Errorf("environment variable %s must be a valid duration: %w", key, err)
	}
	return value, nil
}

func getEnvBoolSafe(key string, defaultValue bool, required bool) (bool, error) {
	valueStr, exists := os.LookupEnv(key)
	if !exists {
		if required {
			return false, fmt.Errorf("environment variable %s is required", key)
		}
		return defaultValue, nil
	}
	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		return false, fmt.Errorf("environment variable %s must be a valid boolean: %w", key, err)
	}
	return value, nil
}

func getEnvEnvironmentSafe(key string, defaultValue Environment, required bool) (Environment, error) {
	env, exists := os.LookupEnv(key)
	if !exists {
		if required {
			return "", fmt.Errorf("environment variable %s is required", key)
		}
		return defaultValue, nil
	}
	envValue := Environment(env)
	if !envValue.IsValid() {
		return "", fmt.Errorf("environment variable %s has invalid value: %s", key, env)
	}
	return envValue, nil
}
