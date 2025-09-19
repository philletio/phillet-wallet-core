package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user in the system
type User struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	UserID      string                 `json:"user_id" db:"user_id"`
	Email       *string                `json:"email,omitempty" db:"email"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
	LastLoginAt *time.Time             `json:"last_login_at,omitempty" db:"last_login_at"`
	IsActive    bool                   `json:"is_active" db:"is_active"`
	Metadata    map[string]interface{} `json:"metadata" db:"metadata"`
}

// Wallet represents a wallet in the system
type Wallet struct {
	ID                uuid.UUID              `json:"id" db:"id"`
	WalletID          string                 `json:"wallet_id" db:"wallet_id"`
	UserID            uuid.UUID              `json:"user_id" db:"user_id"`
	EncryptedMnemonic []byte                 `json:"encrypted_mnemonic" db:"encrypted_mnemonic"`
	MnemonicHash      string                 `json:"mnemonic_hash" db:"mnemonic_hash"`
	Salt              string                 `json:"salt" db:"salt"`
	PassphraseHash    *string                `json:"passphrase_hash,omitempty" db:"passphrase_hash"`
	CreatedAt         time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at" db:"updated_at"`
	LastUsedAt        *time.Time             `json:"last_used_at,omitempty" db:"last_used_at"`
	IsActive          bool                   `json:"is_active" db:"is_active"`
	Metadata          map[string]interface{} `json:"metadata" db:"metadata"`
	User              *User                  `json:"user,omitempty"`
	Addresses         []*Address             `json:"addresses,omitempty"`
}

// Address represents a wallet address
type Address struct {
	ID             uuid.UUID              `json:"id" db:"id"`
	WalletID       uuid.UUID              `json:"wallet_id" db:"wallet_id"`
	Chain          string                 `json:"chain" db:"chain"`
	Address        string                 `json:"address" db:"address"`
	DerivationPath string                 `json:"derivation_path" db:"derivation_path"`
	AddressIndex   int                    `json:"address_index" db:"address_index"`
	IsChange       bool                   `json:"is_change" db:"is_change"`
	PublicKeyHash  *string                `json:"public_key_hash,omitempty" db:"public_key_hash"`
	CreatedAt      time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at" db:"updated_at"`
	LastUsedAt     *time.Time             `json:"last_used_at,omitempty" db:"last_used_at"`
	IsActive       bool                   `json:"is_active" db:"is_active"`
	Metadata       map[string]interface{} `json:"metadata" db:"metadata"`
	Wallet         *Wallet                `json:"wallet,omitempty"`
}

// Transaction represents a blockchain transaction
type Transaction struct {
	ID           uuid.UUID              `json:"id" db:"id"`
	WalletID     uuid.UUID              `json:"wallet_id" db:"wallet_id"`
	AddressID    uuid.UUID              `json:"address_id" db:"address_id"`
	Chain        string                 `json:"chain" db:"chain"`
	TxHash       *string                `json:"tx_hash,omitempty" db:"tx_hash"`
	TxType       string                 `json:"tx_type" db:"tx_type"`
	FromAddress  *string                `json:"from_address,omitempty" db:"from_address"`
	ToAddress    *string                `json:"to_address,omitempty" db:"to_address"`
	Amount       *string                `json:"amount,omitempty" db:"amount"` // Decimal as string
	Fee          *string                `json:"fee,omitempty" db:"fee"`       // Decimal as string
	Status       string                 `json:"status" db:"status"`
	BlockNumber  *int64                 `json:"block_number,omitempty" db:"block_number"`
	BlockHash    *string                `json:"block_hash,omitempty" db:"block_hash"`
	GasUsed      *int64                 `json:"gas_used,omitempty" db:"gas_used"`
	GasPrice     *string                `json:"gas_price,omitempty" db:"gas_price"` // Decimal as string
	Nonce        *int                   `json:"nonce,omitempty" db:"nonce"`
	SignedTxData *string                `json:"signed_tx_data,omitempty" db:"signed_tx_data"`
	RawTxData    map[string]interface{} `json:"raw_tx_data,omitempty" db:"raw_tx_data"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at" db:"updated_at"`
	ConfirmedAt  *time.Time             `json:"confirmed_at,omitempty" db:"confirmed_at"`
	Metadata     map[string]interface{} `json:"metadata" db:"metadata"`
	Wallet       *Wallet                `json:"wallet,omitempty"`
	Address      *Address               `json:"address,omitempty"`
}

// Signature represents a message signature
type Signature struct {
	ID            uuid.UUID              `json:"id" db:"id"`
	WalletID      uuid.UUID              `json:"wallet_id" db:"wallet_id"`
	AddressID     uuid.UUID              `json:"address_id" db:"address_id"`
	MessageHash   string                 `json:"message_hash" db:"message_hash"`
	SignatureData string                 `json:"signature_data" db:"signature_data"`
	SignatureHex  string                 `json:"signature_hex" db:"signature_hex"`
	MessageType   string                 `json:"message_type" db:"message_type"`
	CreatedAt     time.Time              `json:"created_at" db:"created_at"`
	Metadata      map[string]interface{} `json:"metadata" db:"metadata"`
	Wallet        *Wallet                `json:"wallet,omitempty"`
	Address       *Address               `json:"address,omitempty"`
}

// APIKey represents an API key for authentication
type APIKey struct {
	ID          uuid.UUID              `json:"id" db:"id"`
	UserID      uuid.UUID              `json:"user_id" db:"user_id"`
	KeyHash     string                 `json:"key_hash" db:"key_hash"`
	Name        string                 `json:"name" db:"name"`
	Permissions map[string]interface{} `json:"permissions" db:"permissions"`
	LastUsedAt  *time.Time             `json:"last_used_at,omitempty" db:"last_used_at"`
	ExpiresAt   *time.Time             `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
	IsActive    bool                   `json:"is_active" db:"is_active"`
	User        *User                  `json:"user,omitempty"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID           uuid.UUID              `json:"id" db:"id"`
	UserID       *uuid.UUID             `json:"user_id,omitempty" db:"user_id"`
	WalletID     *uuid.UUID             `json:"wallet_id,omitempty" db:"wallet_id"`
	Action       string                 `json:"action" db:"action"`
	ResourceType string                 `json:"resource_type" db:"resource_type"`
	ResourceID   *uuid.UUID             `json:"resource_id,omitempty" db:"resource_id"`
	IPAddress    *string                `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent    *string                `json:"user_agent,omitempty" db:"user_agent"`
	Success      bool                   `json:"success" db:"success"`
	ErrorMessage *string                `json:"error_message,omitempty" db:"error_message"`
	RequestData  map[string]interface{} `json:"request_data,omitempty" db:"request_data"`
	ResponseData map[string]interface{} `json:"response_data,omitempty" db:"response_data"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
	User         *User                  `json:"user,omitempty"`
	Wallet       *Wallet                `json:"wallet,omitempty"`
}

// WalletSummary represents a wallet summary view
type WalletSummary struct {
	ID               uuid.UUID  `json:"id" db:"id"`
	WalletID         string     `json:"wallet_id" db:"wallet_id"`
	UserID           string     `json:"user_id" db:"user_id"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	AddressCount     int64      `json:"address_count" db:"address_count"`
	TransactionCount int64      `json:"transaction_count" db:"transaction_count"`
}

// CreateWalletRequest represents a request to create a wallet
type CreateWalletRequest struct {
	UserID     string `json:"user_id" validate:"required"`
	Mnemonic   string `json:"mnemonic" validate:"required"`
	Passphrase string `json:"passphrase,omitempty"`
}

// CreateAddressRequest represents a request to create an address
type CreateAddressRequest struct {
	WalletID       string `json:"wallet_id" validate:"required"`
	Chain          string `json:"chain" validate:"required"`
	DerivationPath string `json:"derivation_path" validate:"required"`
	AddressIndex   int    `json:"address_index"`
	IsChange       bool   `json:"is_change"`
}

// CreateTransactionRequest represents a request to create a transaction
type CreateTransactionRequest struct {
	WalletID     string                 `json:"wallet_id" validate:"required"`
	AddressID    uuid.UUID              `json:"address_id" validate:"required"`
	Chain        string                 `json:"chain" validate:"required"`
	TxType       string                 `json:"tx_type" validate:"required"`
	FromAddress  string                 `json:"from_address,omitempty"`
	ToAddress    string                 `json:"to_address,omitempty"`
	Amount       string                 `json:"amount,omitempty"`
	Fee          string                 `json:"fee,omitempty"`
	Nonce        *int                   `json:"nonce,omitempty"`
	SignedTxData string                 `json:"signed_tx_data,omitempty"`
	RawTxData    map[string]interface{} `json:"raw_tx_data,omitempty"`
}

// CreateSignatureRequest represents a request to create a signature
type CreateSignatureRequest struct {
	WalletID      string    `json:"wallet_id" validate:"required"`
	AddressID     uuid.UUID `json:"address_id" validate:"required"`
	MessageHash   string    `json:"message_hash" validate:"required"`
	SignatureData string    `json:"signature_data" validate:"required"`
	SignatureHex  string    `json:"signature_hex" validate:"required"`
	MessageType   string    `json:"message_type" validate:"required"`
}
