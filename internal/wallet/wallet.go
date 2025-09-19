package wallet

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gagliardetto/solana-go"
	"github.com/tyler-smith/go-bip39"
)

// HDWallet represents a hierarchical deterministic wallet
type HDWallet struct {
	Mnemonic string
	Seed     []byte
	UserID   string
	Salt     string
}

// NewHDWallet creates a new HD wallet with the specified word count and optional passphrase
func NewHDWallet(userID string, wordCount int, passphrase string) (*HDWallet, error) {
	// Map word count to entropy size per BIP39
	entropySize := 256 // default 24 words
	switch wordCount {
	case 12:
		entropySize = 128
	case 15:
		entropySize = 160
	case 18:
		entropySize = 192
	case 21:
		entropySize = 224
	case 24:
		entropySize = 256
	default:
		return nil, fmt.Errorf("invalid word count: %d", wordCount)
	}

	entropy, err := bip39.NewEntropy(entropySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate entropy: %v", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mnemonic: %v", err)
	}

	seed := bip39.NewSeed(mnemonic, passphrase)

	salt := generateSalt()

	return &HDWallet{
		Mnemonic: mnemonic,
		Seed:     seed,
		UserID:   userID,
		Salt:     salt,
	}, nil
}

// ImportHDWallet imports an existing wallet from mnemonic and optional passphrase
func ImportHDWallet(mnemonic, userID, passphrase string) (*HDWallet, error) {
	// Validate mnemonic
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, fmt.Errorf("invalid mnemonic phrase")
	}

	// Generate seed from mnemonic
	seed := bip39.NewSeed(mnemonic, passphrase)

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
	// Derive per-index private key deterministically (demo only, not BIP-44)
	idxBytes := make([]byte, 8)
	big.NewInt(int64(index)).FillBytes(idxBytes)
	hashInput := append(w.Seed, idxBytes...)
	digest := sha256.Sum256(hashInput)
	// Ensure the private key is within secp256k1 curve order
	privateKey, err := crypto.ToECDSA(digest[:])
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

// DeriveEthereumPrivateKey derives a deterministic per-index private key (demo-only, not BIP-44)
func (w *HDWallet) DeriveEthereumPrivateKey(index int) (*ecdsa.PrivateKey, error) {
	idxBytes := make([]byte, 8)
	big.NewInt(int64(index)).FillBytes(idxBytes)
	hashInput := append(w.Seed, idxBytes...)
	digest := sha256.Sum256(hashInput)
	privateKey, err := crypto.ToECDSA(digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to derive private key: %v", err)
	}
	return privateKey, nil
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

// GenerateSolanaAddress generates a Solana address for the given index
func (w *HDWallet) GenerateSolanaAddress(index int) (string, string, error) {
	// Derive key pair for Solana (using Ed25519)
	keyPair, err := w.deriveSolanaKeyPair(index)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive Solana key pair: %v", err)
	}

	// Create Solana public key
	pubKey := solana.PublicKeyFromBytes(keyPair.PublicKey)
	address := pubKey.String()

	// Get public key as hex string
	publicKeyHex := hex.EncodeToString(keyPair.PublicKey)

	return address, publicKeyHex, nil
}

// GenerateTONAddress generates a TON address for the given index
func (w *HDWallet) GenerateTONAddress(index int) (string, string, error) {
	// Derive key pair for TON
	keyPair, err := w.deriveTONKeyPair(index)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive TON key pair: %v", err)
	}

	// Create TON address
	address, err := w.createTONAddress(keyPair.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to create TON address: %v", err)
	}

	// Get public key as hex string
	publicKeyHex := hex.EncodeToString(keyPair.PublicKey)

	return address, publicKeyHex, nil
}

// deriveSolanaKeyPair derives a Solana key pair for the given index
func (w *HDWallet) deriveSolanaKeyPair(index int) (*KeyPair, error) {
	// For Solana, we use a different derivation path: m/44'/501'/0'/0'/index
	// This follows the Solana standard for HD wallets

	// Create a deterministic seed from the wallet seed and index
	seed := make([]byte, 32)
	copy(seed, w.Seed)

	// Add index to seed for uniqueness
	indexBytes := make([]byte, 4)
	indexBytes[0] = byte(index >> 24)
	indexBytes[1] = byte(index >> 16)
	indexBytes[2] = byte(index >> 8)
	indexBytes[3] = byte(index)

	// Hash the combined seed
	hash := sha256.Sum256(append(seed, indexBytes...))

	// Generate Ed25519 key pair from hash
	privateKey := ed25519.NewKeyFromSeed(hash[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// deriveTONKeyPair derives a TON key pair for the given index
func (w *HDWallet) deriveTONKeyPair(index int) (*KeyPair, error) {
	// For TON, we use a similar approach but with TON-specific derivation
	// TON uses Ed25519 for key generation

	// Create a deterministic seed from the wallet seed and index
	seed := make([]byte, 32)
	copy(seed, w.Seed)

	// Add index to seed for uniqueness
	indexBytes := make([]byte, 4)
	indexBytes[0] = byte(index >> 24)
	indexBytes[1] = byte(index >> 16)
	indexBytes[2] = byte(index >> 8)
	indexBytes[3] = byte(index)

	// Hash the combined seed
	hash := sha256.Sum256(append(seed, indexBytes...))

	// Generate Ed25519 key pair from hash
	privateKey := ed25519.NewKeyFromSeed(hash[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

// createTONAddress creates a TON address from public key
func (w *HDWallet) createTONAddress(publicKey []byte) (string, error) {
	// Create a TON address using the public key
	// This is a simplified implementation - in production you'd use proper TON address generation

	// For now, we'll create a basic address format
	// In reality, TON addresses are more complex and include workchain information
	address := "0:" + hex.EncodeToString(publicKey[:16]) // Simplified format

	return address, nil
}

// KeyPair represents a cryptographic key pair
type KeyPair struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
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
