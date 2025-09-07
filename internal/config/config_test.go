package config

import (
	"os"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	// Test default configuration
	cfg := Load()

	// Test server config
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("Expected server host 0.0.0.0, got %s", cfg.Server.Host)
	}

	if cfg.Server.Port != 50051 {
		t.Errorf("Expected server port 50051, got %d", cfg.Server.Port)
	}

	// Test database config
	if cfg.Database.Host != "localhost" {
		t.Errorf("Expected database host localhost, got %s", cfg.Database.Host)
	}

	if cfg.Database.Port != 5432 {
		t.Errorf("Expected database port 5432, got %d", cfg.Database.Port)
	}

	if cfg.Database.Database != "phillet_wallet" {
		t.Errorf("Expected database name phillet_wallet, got %s", cfg.Database.Database)
	}

	// Test JWT config
	if cfg.JWT.Issuer != "phillet-wallet" {
		t.Errorf("Expected JWT issuer phillet-wallet, got %s", cfg.JWT.Issuer)
	}

	if cfg.JWT.Audience != "wallet-api" {
		t.Errorf("Expected JWT audience wallet-api, got %s", cfg.JWT.Audience)
	}

	if cfg.JWT.Expiration != 24*time.Hour {
		t.Errorf("Expected JWT expiration 24h, got %v", cfg.JWT.Expiration)
	}

	// Test security config
	if cfg.Security.SaltRounds != 12 {
		t.Errorf("Expected salt rounds 12, got %d", cfg.Security.SaltRounds)
	}

	// Test logging config
	if cfg.Logging.Level != "info" {
		t.Errorf("Expected log level info, got %s", cfg.Logging.Level)
	}

	t.Logf("Default configuration loaded successfully")
}

func TestLoadWithEnvironmentVariables(t *testing.T) {
	// Set environment variables
	os.Setenv("SERVER_HOST", "127.0.0.1")
	os.Setenv("SERVER_PORT", "8080")
	os.Setenv("DB_HOST", "db.example.com")
	os.Setenv("DB_PORT", "5433")
	os.Setenv("JWT_SECRET_KEY", "test-secret-key")
	os.Setenv("JWT_EXPIRATION", "1h")
	os.Setenv("SALT_ROUNDS", "16")
	os.Setenv("LOG_LEVEL", "debug")

	// Load configuration
	cfg := Load()

	// Test server config
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Expected server host 127.0.0.1, got %s", cfg.Server.Host)
	}

	if cfg.Server.Port != 8080 {
		t.Errorf("Expected server port 8080, got %d", cfg.Server.Port)
	}

	// Test database config
	if cfg.Database.Host != "db.example.com" {
		t.Errorf("Expected database host db.example.com, got %s", cfg.Database.Host)
	}

	if cfg.Database.Port != 5433 {
		t.Errorf("Expected database port 5433, got %d", cfg.Database.Port)
	}

	// Test JWT config
	if cfg.JWT.SecretKey != "test-secret-key" {
		t.Errorf("Expected JWT secret key test-secret-key, got %s", cfg.JWT.SecretKey)
	}

	if cfg.JWT.Expiration != time.Hour {
		t.Errorf("Expected JWT expiration 1h, got %v", cfg.JWT.Expiration)
	}

	// Test security config
	if cfg.Security.SaltRounds != 16 {
		t.Errorf("Expected salt rounds 16, got %d", cfg.Security.SaltRounds)
	}

	// Test logging config
	if cfg.Logging.Level != "debug" {
		t.Errorf("Expected log level debug, got %s", cfg.Logging.Level)
	}

	// Clean up environment variables
	os.Unsetenv("SERVER_HOST")
	os.Unsetenv("SERVER_PORT")
	os.Unsetenv("DB_HOST")
	os.Unsetenv("DB_PORT")
	os.Unsetenv("JWT_SECRET_KEY")
	os.Unsetenv("JWT_EXPIRATION")
	os.Unsetenv("SALT_ROUNDS")
	os.Unsetenv("LOG_LEVEL")

	t.Logf("Environment variable configuration loaded successfully")
}

func TestGetDSN(t *testing.T) {
	cfg := Load()
	dsn := cfg.GetDSN()

	expectedDSN := "host=localhost port=5432 user=postgres password=password dbname=phillet_wallet sslmode=disable"
	if dsn != expectedDSN {
		t.Errorf("Expected DSN %s, got %s", expectedDSN, dsn)
	}

	t.Logf("DSN generated successfully: %s", dsn)
}

func TestGetServerAddress(t *testing.T) {
	cfg := Load()
	address := cfg.GetServerAddress()

	expectedAddress := "0.0.0.0:50051"
	if address != expectedAddress {
		t.Errorf("Expected server address %s, got %s", expectedAddress, address)
	}

	t.Logf("Server address generated successfully: %s", address)
}

func TestGetEnvAsInt(t *testing.T) {
	// Test valid integer
	os.Setenv("TEST_INT", "42")
	result := getEnvAsInt("TEST_INT", 0)
	if result != 42 {
		t.Errorf("Expected 42, got %d", result)
	}

	// Test invalid integer (should return default)
	os.Setenv("TEST_INVALID_INT", "not-a-number")
	result = getEnvAsInt("TEST_INVALID_INT", 100)
	if result != 100 {
		t.Errorf("Expected 100, got %d", result)
	}

	// Test missing environment variable (should return default)
	result = getEnvAsInt("TEST_MISSING", 200)
	if result != 200 {
		t.Errorf("Expected 200, got %d", result)
	}

	// Clean up
	os.Unsetenv("TEST_INT")
	os.Unsetenv("TEST_INVALID_INT")

	t.Logf("getEnvAsInt tests passed")
}

func TestGetEnvAsDuration(t *testing.T) {
	// Test valid duration
	os.Setenv("TEST_DURATION", "30s")
	result := getEnvAsDuration("TEST_DURATION", time.Minute)
	if result != 30*time.Second {
		t.Errorf("Expected 30s, got %v", result)
	}

	// Test invalid duration (should return default)
	os.Setenv("TEST_INVALID_DURATION", "not-a-duration")
	result = getEnvAsDuration("TEST_INVALID_DURATION", time.Hour)
	if result != time.Hour {
		t.Errorf("Expected 1h, got %v", result)
	}

	// Test missing environment variable (should return default)
	result = getEnvAsDuration("TEST_MISSING", 2*time.Hour)
	if result != 2*time.Hour {
		t.Errorf("Expected 2h, got %v", result)
	}

	// Clean up
	os.Unsetenv("TEST_DURATION")
	os.Unsetenv("TEST_INVALID_DURATION")

	t.Logf("getEnvAsDuration tests passed")
}
