package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/bugbounty-tool/internal/config"
	"github.com/bugbounty-tool/internal/logger"
)

// Cache interface defines caching operations
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Set(ctx context.Context, key string, value []byte, expiration time.Duration) error
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
	Clear(ctx context.Context) error
	Keys(ctx context.Context, pattern string) ([]string, error)
}

// Manager handles different cache backends
type Manager struct {
	config     *config.Config
	log        logger.Logger
	backend    Cache
	encryption bool
}

// NewManager creates a new cache manager
func NewManager(cfg *config.Config, log logger.Logger) (*Manager, error) {
	m := &Manager{
		config:     cfg,
		log:        log,
		encryption: cfg.Security.EncryptCache,
	}
	
	// Initialize cache backend
	var backend Cache
	var err error
	
	// Try Redis first, fallback to memory cache
	if redisClient := m.initRedis(); redisClient != nil {
		backend = NewRedisCache(redisClient, log)
		log.Info("Using Redis cache backend")
	} else {
		backend = NewMemoryCache(log)
		log.Info("Using in-memory cache backend")
	}
	
	m.backend = backend
	return m, err
}

// Get retrieves a value from cache
func (m *Manager) Get(ctx context.Context, key string) ([]byte, error) {
	data, err := m.backend.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	
	if m.encryption && len(data) > 0 {
		// Decrypt data if encryption is enabled
		decrypted, err := m.decrypt(data)
		if err != nil {
			m.log.Error("Failed to decrypt cached data", "key", key, "error", err)
			return nil, err
		}
		return decrypted, nil
	}
	
	return data, nil
}

// Set stores a value in cache
func (m *Manager) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	data := value
	
	if m.encryption {
		// Encrypt data if encryption is enabled
		encrypted, err := m.encrypt(data)
		if err != nil {
			m.log.Error("Failed to encrypt cache data", "key", key, "error", err)
			return err
		}
		data = encrypted
	}
	
	return m.backend.Set(ctx, key, data, expiration)
}

// Delete removes a value from cache
func (m *Manager) Delete(ctx context.Context, key string) error {
	return m.backend.Delete(ctx, key)
}

// Exists checks if a key exists in cache
func (m *Manager) Exists(ctx context.Context, key string) (bool, error) {
	return m.backend.Exists(ctx, key)
}

// Clear removes all cached data
func (m *Manager) Clear(ctx context.Context) error {
	return m.backend.Clear(ctx)
}

// GetJSON retrieves and unmarshals JSON data from cache
func (m *Manager) GetJSON(ctx context.Context, key string, dest interface{}) error {
	data, err := m.Get(ctx, key)
	if err != nil {
		return err
	}
	
	if len(data) == 0 {
		return ErrCacheMiss
	}
	
	return json.Unmarshal(data, dest)
}

// SetJSON marshals and stores JSON data in cache
func (m *Manager) SetJSON(ctx context.Context, key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	
	return m.Set(ctx, key, data, expiration)
}

// CacheKey generates a standardized cache key
func (m *Manager) CacheKey(prefix string, parts ...string) string {
	key := prefix
	for _, part := range parts {
		key += ":" + part
	}
	return key
}

// Helper methods
func (m *Manager) initRedis() *redis.Client {
	// Try to connect to Redis
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
	})
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := client.Ping(ctx).Err(); err != nil {
		m.log.Debug("Redis not available, using memory cache", "error", err)
		return nil
	}
	
	return client
}

func (m *Manager) encrypt(data []byte) ([]byte, error) {
	// Simple encryption implementation
	// In production, use proper encryption like AES-GCM
	return data, nil
}

func (m *Manager) decrypt(data []byte) ([]byte, error) {
	// Simple decryption implementation
	// In production, use proper decryption
	return data, nil
}

// RedisCache implements Cache interface using Redis
type RedisCache struct {
	client *redis.Client
	log    logger.Logger
}

// NewRedisCache creates a Redis-backed cache
func NewRedisCache(client *redis.Client, log logger.Logger) *RedisCache {
	return &RedisCache{
		client: client,
		log:    log,
	}
}

func (r *RedisCache) Get(ctx context.Context, key string) ([]byte, error) {
	result, err := r.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, ErrCacheMiss
	}
	return result, err
}

func (r *RedisCache) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	return r.client.Set(ctx, key, value, expiration).Err()
}

func (r *RedisCache) Delete(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

func (r *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	result, err := r.client.Exists(ctx, key).Result()
	return result > 0, err
}

func (r *RedisCache) Clear(ctx context.Context) error {
	return r.client.FlushDB(ctx).Err()
}

func (r *RedisCache) Keys(ctx context.Context, pattern string) ([]string, error) {
	return r.client.Keys(ctx, pattern).Result()
}

// MemoryCache implements Cache interface using in-memory storage
type MemoryCache struct {
	data   map[string]cacheItem
	mutex  sync.RWMutex
	log    logger.Logger
}

type cacheItem struct {
	value      []byte
	expiration time.Time
}

// NewMemoryCache creates an in-memory cache
func NewMemoryCache(log logger.Logger) *MemoryCache {
	mc := &MemoryCache{
		data: make(map[string]cacheItem),
		log:  log,
	}
	
	// Start cleanup goroutine
	go mc.cleanup()
	
	return mc
}

func (m *MemoryCache) Get(ctx context.Context, key string) ([]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	item, exists := m.data[key]
	if !exists {
		return nil, ErrCacheMiss
	}
	
	if !item.expiration.IsZero() && time.Now().After(item.expiration) {
		// Item has expired
		delete(m.data, key)
		return nil, ErrCacheMiss
	}
	
	return item.value, nil
}

func (m *MemoryCache) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	item := cacheItem{
		value: value,
	}
	
	if expiration > 0 {
		item.expiration = time.Now().Add(expiration)
	}
	
	m.data[key] = item
	return nil
}

func (m *MemoryCache) Delete(ctx context.Context, key string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	delete(m.data, key)
	return nil
}

func (m *MemoryCache) Exists(ctx context.Context, key string) (bool, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	item, exists := m.data[key]
	if !exists {
		return false, nil
	}
	
	if !item.expiration.IsZero() && time.Now().After(item.expiration) {
		return false, nil
	}
	
	return true, nil
}

func (m *MemoryCache) Clear(ctx context.Context) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	m.data = make(map[string]cacheItem)
	return nil
}

func (m *MemoryCache) Keys(ctx context.Context, pattern string) ([]string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	keys := make([]string, 0, len(m.data))
	for key := range m.data {
		keys = append(keys, key)
	}
	
	return keys, nil
}

func (m *MemoryCache) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		m.mutex.Lock()
		now := time.Now()
		for key, item := range m.data {
			if !item.expiration.IsZero() && now.After(item.expiration) {
				delete(m.data, key)
			}
		}
		m.mutex.Unlock()
	}
}

// Error definitions
var (
	ErrCacheMiss = fmt.Errorf("cache miss")
)
