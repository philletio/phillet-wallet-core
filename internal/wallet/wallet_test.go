package wallet

import (
	"testing"
)

func TestNewHDWallet(t *testing.T) {
	userID := "test_user_123"

	wallet, err := NewHDWallet(userID)
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	if wallet.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, wallet.UserID)
	}

	if wallet.Mnemonic == "" {
		t.Error("Expected non-empty mnemonic")
	}

	if len(wallet.Seed) == 0 {
		t.Error("Expected non-empty seed")
	}

	t.Logf("Generated wallet for user: %s", wallet.UserID)
	t.Logf("Mnemonic: %s", wallet.Mnemonic)
}

func TestImportHDWallet(t *testing.T) {
	// Test with valid mnemonic
	validMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	userID := "test_user_456"

	wallet, err := ImportHDWallet(validMnemonic, userID)
	if err != nil {
		t.Fatalf("Failed to import wallet: %v", err)
	}

	if wallet.UserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, wallet.UserID)
	}

	if wallet.Mnemonic != validMnemonic {
		t.Errorf("Expected mnemonic %s, got %s", validMnemonic, wallet.Mnemonic)
	}

	// Test with invalid mnemonic
	invalidMnemonic := "invalid mnemonic phrase"
	_, err = ImportHDWallet(invalidMnemonic, userID)
	if err == nil {
		t.Error("Expected error for invalid mnemonic")
	}
}

func TestGenerateEthereumAddress(t *testing.T) {
	wallet, err := NewHDWallet("test_user_789")
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	address, privateKey, err := wallet.GenerateEthereumAddress(0)
	if err != nil {
		t.Fatalf("Failed to generate address: %v", err)
	}

	if address == "" {
		t.Error("Expected non-empty address")
	}

	if privateKey == "" {
		t.Error("Expected non-nil private key")
	}

	t.Logf("Generated Ethereum address: %s", address)
}

func TestSignAndVerifyMessage(t *testing.T) {
	wallet, err := NewHDWallet("test_user_sign")
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	address, privateKey, err := wallet.GenerateEthereumAddress(0)
	if err != nil {
		t.Fatalf("Failed to generate address: %v", err)
	}

	// Test message
	message := []byte("Hello, Philosopher's Wallet!")

	// Sign message
	signature, err := wallet.SignMessage(message, privateKey)
	if err != nil {
		t.Fatalf("Failed to sign message: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Expected non-empty signature")
	}

	// Verify signature
	valid, err := VerifySignature(message, signature, address)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if !valid {
		t.Error("Expected signature to be valid")
	}

	// Test with wrong message
	wrongMessage := []byte("Wrong message")
	valid, err = VerifySignature(wrongMessage, signature, address)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	if valid {
		t.Error("Expected signature to be invalid for wrong message")
	}

	t.Logf("Successfully signed and verified message")
}
