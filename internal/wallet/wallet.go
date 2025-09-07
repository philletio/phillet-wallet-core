package wallet

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip39"
)

// HDWallet represents a hierarchical deterministic wallet
type HDWallet struct {
	Mnemonic string
	Seed     []byte
	UserID   string
	Salt     string
}

// NewHDWallet creates a new HD wallet
func NewHDWallet(userID string) (*HDWallet, error) {
	// Generate entropy for 24-word mnemonic
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return nil, fmt.Errorf("failed to generate entropy: %v", err)
	}

	// Generate mnemonic
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mnemonic: %v", err)
	}

	// Generate seed from mnemonic
	seed := bip39.NewSeed(mnemonic, "")

	// Generate salt
	salt := generateSalt()

	return &HDWallet{
		Mnemonic: mnemonic,
		Seed:     seed,
		UserID:   userID,
		Salt:     salt,
	}, nil
}

// ImportHDWallet imports an existing wallet from mnemonic
func ImportHDWallet(mnemonic, userID string) (*HDWallet, error) {
	// Validate mnemonic
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic phrase")
	}

	// Generate seed from mnemonic
	seed := bip39.NewSeed(mnemonic, "")

	// Generate salt
	salt := generateSalt()

	return &HDWallet{
		Mnemonic: mnemonic,
		Seed:     seed,
		UserID:   userID,
		Salt:     salt,
	}, nil
}

// GenerateEthereumAddress generates an Ethereum address
func (w *HDWallet) GenerateEthereumAddress(index int) (string, string, error) {
	// Derive private key from seed (simplified version)
	// In production, use proper BIP-44 derivation
	privateKey, err := crypto.ToECDSA(w.Seed[:32])
	if err != nil {
		return "", "", fmt.Errorf("failed to create private key: %v", err)
	}

	// Get public key
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", "", fmt.Errorf("failed to get public key")
	}

	// Generate address
	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	// Hash public key for storage
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	publicKeyHash := sha256.Sum256(publicKeyBytes)
	publicKeyHashHex := hex.EncodeToString(publicKeyHash[:])

	return address.Hex(), publicKeyHashHex, nil
}

// SignMessage signs a message with the wallet's private key
func (w *HDWallet) SignMessage(message []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	// Hash the message
	hash := crypto.Keccak256(message)

	// Sign the hash
	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %v", err)
	}

	return signature, nil
}

// VerifySignature verifies a signature
func VerifySignature(message, signature []byte, address string) (bool, error) {
	// Hash the message
	hash := crypto.Keccak256(message)

	// Recover public key from signature
	publicKey, err := crypto.SigToPub(hash, signature)
	if err != nil {
		return false, fmt.Errorf("failed to recover public key: %v", err)
	}

	// Get address from public key
	recoveredAddress := crypto.PubkeyToAddress(*publicKey)

	// Compare addresses
	return recoveredAddress.Hex() == address, nil
}

// GetMnemonic returns the mnemonic phrase
func (w *HDWallet) GetMnemonic() string {
	return w.Mnemonic
}

// GetMnemonicHash returns the hash of the mnemonic phrase
func (w *HDWallet) GetMnemonicHash() string {
	hash := sha256.Sum256([]byte(w.Mnemonic))
	return hex.EncodeToString(hash[:])
}

// GetSalt returns the salt
func (w *HDWallet) GetSalt() string {
	return w.Salt
}

// GetUserID returns the user ID
func (w *HDWallet) GetUserID() string {
	return w.UserID
}

// generateSalt generates a random salt
func generateSalt() string {
	salt := make([]byte, 32)
	rand.Read(salt)
	return hex.EncodeToString(salt)
}
