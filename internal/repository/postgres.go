package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/philletio/phillet-wallet-core/internal/models"
)

// PostgresRepository implements database operations
type PostgresRepository struct {
	db *sql.DB
}

// NewPostgresRepository creates a new PostgreSQL repository
func NewPostgresRepository(db *sql.DB) *PostgresRepository {
	return &PostgresRepository{db: db}
}

// NewPostgresConnection creates a new database connection
func NewPostgresConnection(config interface{}) (*sql.DB, error) {
	// Convert config to DSN string
	dsn := ""
	switch cfg := config.(type) {
	case string:
		dsn = cfg
	default:
		// Try to get DSN from config struct
		if getDSN, ok := config.(interface{ GetDSN() string }); ok {
			dsn = getDSN.GetDSN()
		} else {
			return nil, fmt.Errorf("unsupported config type")
		}
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}

	return db, nil
}

// Close closes the database connection
func (r *PostgresRepository) Close() error {
	return r.db.Close()
}

// Ping tests the database connection
func (r *PostgresRepository) Ping(ctx context.Context) error {
	return r.db.PingContext(ctx)
}

// User operations
func (r *PostgresRepository) CreateUser(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (id, user_id, email, created_at, updated_at, is_active, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.db.ExecContext(ctx, query,
		user.ID, user.UserID, user.Email, user.CreatedAt, user.UpdatedAt, user.IsActive, user.Metadata)

	return err
}

func (r *PostgresRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	query := `SELECT id, user_id, email, created_at, updated_at, last_login_at, is_active, metadata FROM users WHERE id = $1`

	var user models.User
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID, &user.UserID, &user.Email, &user.CreatedAt, &user.UpdatedAt,
		&user.LastLoginAt, &user.IsActive, &user.Metadata)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (r *PostgresRepository) GetUserByUserID(ctx context.Context, userID string) (*models.User, error) {
	query := `SELECT id, user_id, email, created_at, updated_at, last_login_at, is_active, metadata FROM users WHERE user_id = $1`

	var user models.User
	err := r.db.QueryRowContext(ctx, query, userID).Scan(
		&user.ID, &user.UserID, &user.Email, &user.CreatedAt, &user.UpdatedAt,
		&user.LastLoginAt, &user.IsActive, &user.Metadata)

	if err != nil {
		return nil, err
	}

	return &user, nil
}

// Wallet operations
func (r *PostgresRepository) CreateWallet(ctx context.Context, wallet *models.Wallet) error {
	query := `
		INSERT INTO wallets (id, wallet_id, user_id, mnemonic_hash, salt, passphrase_hash, created_at, updated_at, is_active, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err := r.db.ExecContext(ctx, query,
		wallet.ID, wallet.WalletID, wallet.UserID, wallet.MnemonicHash, wallet.Salt,
		wallet.PassphraseHash, wallet.CreatedAt, wallet.UpdatedAt, wallet.IsActive, wallet.Metadata)

	return err
}

func (r *PostgresRepository) GetWalletByID(ctx context.Context, id uuid.UUID) (*models.Wallet, error) {
	query := `
		SELECT id, wallet_id, user_id, mnemonic_hash, salt, passphrase_hash, created_at, updated_at, last_used_at, is_active, metadata
		FROM wallets WHERE id = $1
	`

	var wallet models.Wallet
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&wallet.ID, &wallet.WalletID, &wallet.UserID, &wallet.MnemonicHash, &wallet.Salt,
		&wallet.PassphraseHash, &wallet.CreatedAt, &wallet.UpdatedAt, &wallet.LastUsedAt,
		&wallet.IsActive, &wallet.Metadata)

	if err != nil {
		return nil, err
	}

	return &wallet, nil
}

func (r *PostgresRepository) GetWalletByWalletID(ctx context.Context, walletID string) (*models.Wallet, error) {
	query := `
		SELECT id, wallet_id, user_id, mnemonic_hash, salt, passphrase_hash, created_at, updated_at, last_used_at, is_active, metadata
		FROM wallets WHERE wallet_id = $1
	`

	var wallet models.Wallet
	err := r.db.QueryRowContext(ctx, query, walletID).Scan(
		&wallet.ID, &wallet.WalletID, &wallet.UserID, &wallet.MnemonicHash, &wallet.Salt,
		&wallet.PassphraseHash, &wallet.CreatedAt, &wallet.UpdatedAt, &wallet.LastUsedAt,
		&wallet.IsActive, &wallet.Metadata)

	if err != nil {
		return nil, err
	}

	return &wallet, nil
}

func (r *PostgresRepository) GetWalletsByUserID(ctx context.Context, userID uuid.UUID) ([]*models.Wallet, error) {
	query := `
		SELECT id, wallet_id, user_id, mnemonic_hash, salt, passphrase_hash, created_at, updated_at, last_used_at, is_active, metadata
		FROM wallets WHERE user_id = $1 AND is_active = true
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var wallets []*models.Wallet
	for rows.Next() {
		var wallet models.Wallet
		err := rows.Scan(
			&wallet.ID, &wallet.WalletID, &wallet.UserID, &wallet.MnemonicHash, &wallet.Salt,
			&wallet.PassphraseHash, &wallet.CreatedAt, &wallet.UpdatedAt, &wallet.LastUsedAt,
			&wallet.IsActive, &wallet.Metadata)
		if err != nil {
			return nil, err
		}
		wallets = append(wallets, &wallet)
	}

	return wallets, nil
}

func (r *PostgresRepository) UpdateWalletLastUsed(ctx context.Context, walletID uuid.UUID) error {
	query := `UPDATE wallets SET last_used_at = $1 WHERE id = $2`
	_, err := r.db.ExecContext(ctx, query, time.Now(), walletID)
	return err
}

// Address operations
func (r *PostgresRepository) CreateAddress(ctx context.Context, address *models.Address) error {
	query := `
		INSERT INTO addresses (id, wallet_id, chain, address, derivation_path, address_index, is_change, public_key_hash, created_at, updated_at, is_active, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := r.db.ExecContext(ctx, query,
		address.ID, address.WalletID, address.Chain, address.Address, address.DerivationPath,
		address.AddressIndex, address.IsChange, address.PublicKeyHash, address.CreatedAt,
		address.UpdatedAt, address.IsActive, address.Metadata)

	return err
}

func (r *PostgresRepository) GetAddressesByWalletID(ctx context.Context, walletID uuid.UUID) ([]*models.Address, error) {
	query := `
		SELECT id, wallet_id, chain, address, derivation_path, address_index, is_change, public_key_hash, created_at, updated_at, last_used_at, is_active, metadata
		FROM addresses WHERE wallet_id = $1 AND is_active = true
		ORDER BY address_index ASC
	`

	rows, err := r.db.QueryContext(ctx, query, walletID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var addresses []*models.Address
	for rows.Next() {
		var address models.Address
		err := rows.Scan(
			&address.ID, &address.WalletID, &address.Chain, &address.Address, &address.DerivationPath,
			&address.AddressIndex, &address.IsChange, &address.PublicKeyHash, &address.CreatedAt,
			&address.UpdatedAt, &address.LastUsedAt, &address.IsActive, &address.Metadata)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, &address)
	}

	return addresses, nil
}

func (r *PostgresRepository) GetAddressesByWalletIDString(ctx context.Context, walletID string) ([]*models.Address, error) {
	query := `
		SELECT id, wallet_id, chain, address, derivation_path, address_index, is_change, public_key_hash, created_at, updated_at, last_used_at, is_active, metadata
		FROM addresses WHERE wallet_id = $1 AND is_active = true
		ORDER BY address_index ASC
	`

	rows, err := r.db.QueryContext(ctx, query, walletID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var addresses []*models.Address
	for rows.Next() {
		var address models.Address
		err := rows.Scan(
			&address.ID, &address.WalletID, &address.Chain, &address.Address, &address.DerivationPath,
			&address.AddressIndex, &address.IsChange, &address.PublicKeyHash, &address.CreatedAt,
			&address.UpdatedAt, &address.LastUsedAt, &address.IsActive, &address.Metadata)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, &address)
	}

	return addresses, nil
}

func (r *PostgresRepository) GetAddressByIndex(ctx context.Context, walletID uuid.UUID, chain string, addressIndex int) (*models.Address, error) {
	query := `
		SELECT id, wallet_id, chain, address, derivation_path, address_index, is_change, public_key_hash, created_at, updated_at, last_used_at, is_active, metadata
		FROM addresses WHERE wallet_id = $1 AND chain = $2 AND address_index = $3 AND is_active = true
	`

	var address models.Address
	err := r.db.QueryRowContext(ctx, query, walletID, chain, addressIndex).Scan(
		&address.ID, &address.WalletID, &address.Chain, &address.Address, &address.DerivationPath,
		&address.AddressIndex, &address.IsChange, &address.PublicKeyHash, &address.CreatedAt,
		&address.UpdatedAt, &address.LastUsedAt, &address.IsActive, &address.Metadata)

	if err != nil {
		return nil, err
	}

	return &address, nil
}

func (r *PostgresRepository) GetAddressByWalletAndIndex(ctx context.Context, walletID string, addressIndex int32) (*models.Address, error) {
	query := `
		SELECT id, wallet_id, chain, address, derivation_path, address_index, is_change, public_key_hash, created_at, updated_at, last_used_at, is_active, metadata
		FROM addresses WHERE wallet_id = $1 AND address_index = $2 AND is_active = true
	`

	var address models.Address
	err := r.db.QueryRowContext(ctx, query, walletID, addressIndex).Scan(
		&address.ID, &address.WalletID, &address.Chain, &address.Address, &address.DerivationPath,
		&address.AddressIndex, &address.IsChange, &address.PublicKeyHash, &address.CreatedAt,
		&address.UpdatedAt, &address.LastUsedAt, &address.IsActive, &address.Metadata)

	if err != nil {
		return nil, err
	}

	return &address, nil
}

// Transaction operations
func (r *PostgresRepository) CreateTransaction(ctx context.Context, tx *models.Transaction) error {
	query := `
		INSERT INTO transactions (id, wallet_id, address_id, chain, tx_hash, tx_type, from_address, to_address, amount, fee, status, block_number, block_hash, gas_used, gas_price, nonce, signed_tx_data, raw_tx_data, created_at, updated_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21)
	`

	_, err := r.db.ExecContext(ctx, query,
		tx.ID, tx.WalletID, tx.AddressID, tx.Chain, tx.TxHash, tx.TxType, tx.FromAddress,
		tx.ToAddress, tx.Amount, tx.Fee, tx.Status, tx.BlockNumber, tx.BlockHash,
		tx.GasUsed, tx.GasPrice, tx.Nonce, tx.SignedTxData, tx.RawTxData,
		tx.CreatedAt, tx.UpdatedAt, tx.Metadata)

	return err
}

func (r *PostgresRepository) GetTransactionsByWalletID(ctx context.Context, walletID uuid.UUID, limit, offset int) ([]*models.Transaction, error) {
	query := `
		SELECT id, wallet_id, address_id, chain, tx_hash, tx_type, from_address, to_address, amount, fee, status, block_number, block_hash, gas_used, gas_price, nonce, signed_tx_data, raw_tx_data, created_at, updated_at, confirmed_at, metadata
		FROM transactions WHERE wallet_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.db.QueryContext(ctx, query, walletID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var transactions []*models.Transaction
	for rows.Next() {
		var tx models.Transaction
		err := rows.Scan(
			&tx.ID, &tx.WalletID, &tx.AddressID, &tx.Chain, &tx.TxHash, &tx.TxType,
			&tx.FromAddress, &tx.ToAddress, &tx.Amount, &tx.Fee, &tx.Status,
			&tx.BlockNumber, &tx.BlockHash, &tx.GasUsed, &tx.GasPrice, &tx.Nonce,
			&tx.SignedTxData, &tx.RawTxData, &tx.CreatedAt, &tx.UpdatedAt,
			&tx.ConfirmedAt, &tx.Metadata)
		if err != nil {
			return nil, err
		}
		transactions = append(transactions, &tx)
	}

	return transactions, nil
}

// Signature operations
func (r *PostgresRepository) CreateSignature(ctx context.Context, sig *models.Signature) error {
	query := `
		INSERT INTO signatures (id, wallet_id, address_id, message_hash, signature_data, signature_hex, message_type, created_at, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := r.db.ExecContext(ctx, query,
		sig.ID, sig.WalletID, sig.AddressID, sig.MessageHash, sig.SignatureData,
		sig.SignatureHex, sig.MessageType, sig.CreatedAt, sig.Metadata)

	return err
}

// Audit log operations
func (r *PostgresRepository) CreateAuditLog(ctx context.Context, log *models.AuditLog) error {
	query := `
		INSERT INTO audit_logs (id, user_id, wallet_id, action, resource_type, resource_id, ip_address, user_agent, success, error_message, request_data, response_data, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	_, err := r.db.ExecContext(ctx, query,
		log.ID, log.UserID, log.WalletID, log.Action, log.ResourceType, log.ResourceID,
		log.IPAddress, log.UserAgent, log.Success, log.ErrorMessage, log.RequestData,
		log.ResponseData, log.CreatedAt)

	return err
}

// Wallet summary operations
func (r *PostgresRepository) GetWalletSummary(ctx context.Context, walletID uuid.UUID) (*models.WalletSummary, error) {
	query := `
		SELECT id, wallet_id, user_id, created_at, last_used_at, address_count, transaction_count
		FROM wallet_summary WHERE id = $1
	`

	var summary models.WalletSummary
	err := r.db.QueryRowContext(ctx, query, walletID).Scan(
		&summary.ID, &summary.WalletID, &summary.UserID, &summary.CreatedAt,
		&summary.LastUsedAt, &summary.AddressCount, &summary.TransactionCount)

	if err != nil {
		return nil, err
	}

	return &summary, nil
}
