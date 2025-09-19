package wallet

import (
	"testing"
)

func TestNewHDWallet(t *testing.T) {
	userID := "test_user_123"

	wallet, err := NewHDWallet(userID, 12, "")
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

	wallet, err := ImportHDWallet(validMnemonic, userID, "")
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
	_, err = ImportHDWallet(invalidMnemonic, userID, "")
	if err == nil {
		t.Error("Expected error for invalid mnemonic")
	}
}

func TestGenerateEthereumAddress(t *testing.T) {
	wallet, err := NewHDWallet("test_user_789", 12, "")
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
	wallet, err := NewHDWallet("test_user_sign", 12, "")
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	address, _, err := wallet.GenerateEthereumAddress(0)
	if err != nil {
		t.Fatalf("Failed to generate address: %v", err)
	}

	// Get private key for signing
	privateKey, err := wallet.DeriveEthereumPrivateKey(0)
	if err != nil {
		t.Fatalf("Failed to derive private key: %v", err)
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

func TestGenerateSolanaAddress(t *testing.T) {
	wallet, err := NewHDWallet("test_user_solana", 12, "")
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	address, publicKey, err := wallet.GenerateSolanaAddress(0)
	if err != nil {
		t.Fatalf("Failed to generate Solana address: %v", err)
	}

	if address == "" {
		t.Error("Expected non-empty Solana address")
	}

	if publicKey == "" {
		t.Error("Expected non-empty public key")
	}

	t.Logf("Generated Solana address: %s", address)
	t.Logf("Public key: %s", publicKey)
}

func TestGenerateTONAddress(t *testing.T) {
	wallet, err := NewHDWallet("test_user_ton", 12, "")
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	address, publicKey, err := wallet.GenerateTONAddress(0)
	if err != nil {
		t.Fatalf("Failed to generate TON address: %v", err)
	}

	if address == "" {
		t.Error("Expected non-empty TON address")
	}

	if publicKey == "" {
		t.Error("Expected non-empty public key")
	}

	t.Logf("Generated TON address: %s", address)
	t.Logf("Public key: %s", publicKey)
}

func TestMultipleAddressGeneration(t *testing.T) {
	wallet, err := NewHDWallet("test_user_multi", 12, "")
	if err != nil {
		t.Fatalf("Failed to create wallet: %v", err)
	}

	// Generate multiple addresses for different chains
	ethAddress, _, err := wallet.GenerateEthereumAddress(0)
	if err != nil {
		t.Fatalf("Failed to generate Ethereum address: %v", err)
	}

	solAddress, _, err := wallet.GenerateSolanaAddress(0)
	if err != nil {
		t.Fatalf("Failed to generate Solana address: %v", err)
	}

	tonAddress, _, err := wallet.GenerateTONAddress(0)
	if err != nil {
		t.Fatalf("Failed to generate TON address: %v", err)
	}

	// Verify addresses are different
	if ethAddress == solAddress || ethAddress == tonAddress || solAddress == tonAddress {
		t.Error("Expected different addresses for different chains")
	}

	t.Logf("Ethereum address: %s", ethAddress)
	t.Logf("Solana address: %s", solAddress)
	t.Logf("TON address: %s", tonAddress)
}
