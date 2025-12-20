package config

import (
	"testing"
	"time"
)

func TestLoad_Defaults(t *testing.T) {
	// Clear any existing env vars using t.Setenv which handles cleanup
	envVars := []string{
		"RDAP_LISTEN_ADDR",
		"RDAP_READ_TIMEOUT",
		"RDAP_WRITE_TIMEOUT",
		"RDAP_SHUTDOWN_TIMEOUT",
		"RDAP_CACHE_TTL",
		"RDAP_CACHE_NEGATIVE_TTL",
		"RDAP_CACHE_RAM_ENABLED",
		"RDAP_CACHE_RAM_MAX_SIZE",
		"RDAP_CACHE_REDIS_ENABLED",
		"RDAP_CACHE_REDIS_ADDR",
		"RDAP_CLIENT_TIMEOUT",
		"RDAP_CLIENT_MAX_RETRIES",
		"RDAP_BOOTSTRAP_REFRESH",
		"RDAP_LOG_LEVEL",
		"RDAP_LOG_FORMAT",
	}

	for _, env := range envVars {
		t.Setenv(env, "")
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Server defaults
	if cfg.Server.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %v, want :8080", cfg.Server.ListenAddr)
	}
	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout = %v, want 30s", cfg.Server.ReadTimeout)
	}
	if cfg.Server.WriteTimeout != 30*time.Second {
		t.Errorf("WriteTimeout = %v, want 30s", cfg.Server.WriteTimeout)
	}
	if cfg.Server.ShutdownTimeout != 30*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 30s", cfg.Server.ShutdownTimeout)
	}

	// Cache defaults
	if cfg.Cache.TTL != 24*time.Hour {
		t.Errorf("Cache.TTL = %v, want 24h", cfg.Cache.TTL)
	}
	if cfg.Cache.NegativeTTL != 1*time.Hour {
		t.Errorf("Cache.NegativeTTL = %v, want 1h", cfg.Cache.NegativeTTL)
	}
	if !cfg.Cache.RAM.Enabled {
		t.Error("Cache.RAM.Enabled = false, want true")
	}
	if cfg.Cache.RAM.MaxSize != 100*1024*1024 {
		t.Errorf("Cache.RAM.MaxSize = %v, want 100MB", cfg.Cache.RAM.MaxSize)
	}
	if cfg.Cache.Redis.Enabled {
		t.Error("Cache.Redis.Enabled = true, want false")
	}

	// RDAP defaults
	if cfg.RDAP.Timeout != 10*time.Second {
		t.Errorf("RDAP.Timeout = %v, want 10s", cfg.RDAP.Timeout)
	}
	if cfg.RDAP.MaxRetries != 2 {
		t.Errorf("RDAP.MaxRetries = %v, want 2", cfg.RDAP.MaxRetries)
	}

	// Bootstrap defaults
	if cfg.Bootstrap.RefreshInterval != 24*time.Hour {
		t.Errorf("Bootstrap.RefreshInterval = %v, want 24h", cfg.Bootstrap.RefreshInterval)
	}

	// Log defaults
	if cfg.Log.Level != "info" {
		t.Errorf("Log.Level = %v, want info", cfg.Log.Level)
	}
	if cfg.Log.Format != "json" {
		t.Errorf("Log.Format = %v, want json", cfg.Log.Format)
	}
}

func TestLoad_CustomValues(t *testing.T) {
	t.Setenv("RDAP_LISTEN_ADDR", ":9090")
	t.Setenv("RDAP_READ_TIMEOUT", "60s")
	t.Setenv("RDAP_CACHE_TTL", "12h")
	t.Setenv("RDAP_CACHE_RAM_MAX_SIZE", "200MB")
	t.Setenv("RDAP_LOG_LEVEL", "debug")
	t.Setenv("RDAP_LOG_FORMAT", "text")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Server.ListenAddr != ":9090" {
		t.Errorf("ListenAddr = %v, want :9090", cfg.Server.ListenAddr)
	}
	if cfg.Server.ReadTimeout != 60*time.Second {
		t.Errorf("ReadTimeout = %v, want 60s", cfg.Server.ReadTimeout)
	}
	if cfg.Cache.TTL != 12*time.Hour {
		t.Errorf("Cache.TTL = %v, want 12h", cfg.Cache.TTL)
	}
	if cfg.Cache.RAM.MaxSize != 200*1024*1024 {
		t.Errorf("Cache.RAM.MaxSize = %v, want 200MB", cfg.Cache.RAM.MaxSize)
	}
	if cfg.Log.Level != "debug" {
		t.Errorf("Log.Level = %v, want debug", cfg.Log.Level)
	}
	if cfg.Log.Format != "text" {
		t.Errorf("Log.Format = %v, want text", cfg.Log.Format)
	}
}

func TestLoad_RedisEnabled(t *testing.T) {
	t.Setenv("RDAP_CACHE_REDIS_ENABLED", "true")
	t.Setenv("RDAP_CACHE_REDIS_ADDR", "localhost:6379")
	t.Setenv("RDAP_CACHE_REDIS_PASSWORD", "secret")
	t.Setenv("RDAP_CACHE_REDIS_DB", "1")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !cfg.Cache.Redis.Enabled {
		t.Error("Cache.Redis.Enabled = false, want true")
	}
	if cfg.Cache.Redis.Addr != "localhost:6379" {
		t.Errorf("Cache.Redis.Addr = %v, want localhost:6379", cfg.Cache.Redis.Addr)
	}
	if cfg.Cache.Redis.Password != "secret" {
		t.Errorf("Cache.Redis.Password = %v, want secret", cfg.Cache.Redis.Password)
	}
	if cfg.Cache.Redis.DB != 1 {
		t.Errorf("Cache.Redis.DB = %v, want 1", cfg.Cache.Redis.DB)
	}
}

func TestLoad_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr string
	}{
		{
			name:    "invalid log level",
			envVars: map[string]string{"RDAP_LOG_LEVEL": "invalid"},
			wantErr: "invalid log level",
		},
		{
			name:    "invalid log format",
			envVars: map[string]string{"RDAP_LOG_FORMAT": "xml"},
			wantErr: "invalid log format",
		},
		{
			name:    "redis enabled without addr",
			envVars: map[string]string{"RDAP_CACHE_REDIS_ENABLED": "true"},
			wantErr: "redis address required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear env vars using t.Setenv for proper cleanup
			t.Setenv("RDAP_LOG_LEVEL", "")
			t.Setenv("RDAP_LOG_FORMAT", "")
			t.Setenv("RDAP_CACHE_REDIS_ENABLED", "")
			t.Setenv("RDAP_CACHE_REDIS_ADDR", "")

			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			_, err := Load()
			if err == nil {
				t.Fatal("Load() expected error, got nil")
			}
			if !contains(err.Error(), tt.wantErr) {
				t.Errorf("Load() error = %v, want to contain %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetSizeEnv(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		defValue int64
		want     int64
	}{
		{"empty", "", 100, 100},
		{"plain number", "1024", 0, 1024},
		{"bytes", "1024B", 0, 1024},
		{"kilobytes", "10KB", 0, 10 * 1024},
		{"megabytes", "100MB", 0, 100 * 1024 * 1024},
		{"gigabytes", "2GB", 0, 2 * 1024 * 1024 * 1024},
		{"lowercase mb", "50mb", 0, 50 * 1024 * 1024},
		{"invalid", "invalid", 999, 999},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envKey := "TEST_SIZE_ENV_" + tt.name
			t.Setenv(envKey, tt.value)

			got := getSizeEnv(envKey, tt.defValue)
			if got != tt.want {
				t.Errorf("getSizeEnv() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetDurationEnv(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		defValue time.Duration
		want     time.Duration
	}{
		{"empty", "", 10 * time.Second, 10 * time.Second},
		{"seconds", "30s", 0, 30 * time.Second},
		{"minutes", "5m", 0, 5 * time.Minute},
		{"hours", "24h", 0, 24 * time.Hour},
		{"invalid", "invalid", 99 * time.Second, 99 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envKey := "TEST_DURATION_ENV_" + tt.name
			t.Setenv(envKey, tt.value)

			got := getDurationEnv(envKey, tt.defValue)
			if got != tt.want {
				t.Errorf("getDurationEnv() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetBoolEnv(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		defValue bool
		want     bool
	}{
		{"empty", "", true, true},
		{"true", "true", false, true},
		{"false", "false", true, false},
		{"1", "1", false, true},
		{"0", "0", true, false},
		{"invalid", "invalid", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envKey := "TEST_BOOL_ENV_" + tt.name
			t.Setenv(envKey, tt.value)

			got := getBoolEnv(envKey, tt.defValue)
			if got != tt.want {
				t.Errorf("getBoolEnv() = %v, want %v", got, tt.want)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
