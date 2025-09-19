-- Phillet Wallet Core - Initial Database Schema
-- Migration: 001_initial_schema.sql

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_login_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Wallets table
CREATE TABLE wallets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    wallet_id VARCHAR(255) UNIQUE NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_mnemonic BYTEA,
    mnemonic_hash VARCHAR(255) NOT NULL, -- Hashed mnemonic for security
    salt VARCHAR(255) NOT NULL, -- Salt for mnemonic hashing
    passphrase_hash VARCHAR(255), -- Optional passphrase hash
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Addresses table
CREATE TABLE addresses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    chain VARCHAR(50) NOT NULL, -- ETHEREUM, POLYGON, BSC, SOLANA, TON
    address VARCHAR(255) NOT NULL,
    derivation_path VARCHAR(255) NOT NULL,
    address_index INTEGER NOT NULL DEFAULT 0,
    is_change BOOLEAN DEFAULT FALSE,
    public_key_hash VARCHAR(255), -- Hashed public key for security
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}'::jsonb,
    UNIQUE(wallet_id, chain, address_index)
);

-- Transactions table
CREATE TABLE transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    address_id UUID NOT NULL REFERENCES addresses(id) ON DELETE CASCADE,
    chain VARCHAR(50) NOT NULL,
    tx_hash VARCHAR(255) UNIQUE,
    tx_type VARCHAR(50) NOT NULL, -- SEND, RECEIVE, SWAP, etc.
    from_address VARCHAR(255),
    to_address VARCHAR(255),
    amount DECIMAL(65, 18), -- Large decimal for crypto amounts
    fee DECIMAL(65, 18),
    status VARCHAR(50) DEFAULT 'PENDING', -- PENDING, CONFIRMED, FAILED
    block_number BIGINT,
    block_hash VARCHAR(255),
    gas_used BIGINT,
    gas_price DECIMAL(65, 18),
    nonce INTEGER,
    signed_tx_data TEXT, -- Encrypted signed transaction data
    raw_tx_data JSONB, -- Raw transaction data
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    confirmed_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Signatures table
CREATE TABLE signatures (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    address_id UUID NOT NULL REFERENCES addresses(id) ON DELETE CASCADE,
    message_hash VARCHAR(255) NOT NULL,
    signature_data TEXT NOT NULL, -- Encrypted signature data
    signature_hex VARCHAR(255) NOT NULL,
    message_type VARCHAR(50) NOT NULL, -- TRANSACTION, MESSAGE, etc.
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'::jsonb
);

-- API Keys table
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash VARCHAR(255) UNIQUE NOT NULL, -- Hashed API key
    name VARCHAR(255) NOT NULL,
    permissions JSONB DEFAULT '{}'::jsonb,
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

-- Audit Log table
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    wallet_id UUID REFERENCES wallets(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL, -- CREATE_WALLET, SIGN_TX, etc.
    resource_type VARCHAR(50) NOT NULL, -- WALLET, ADDRESS, TRANSACTION, etc.
    resource_id UUID,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    error_message TEXT,
    request_data JSONB,
    response_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_users_user_id ON users(user_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_wallets_wallet_id ON wallets(wallet_id);
CREATE INDEX idx_wallets_user_id ON wallets(user_id);
CREATE INDEX idx_addresses_wallet_id ON addresses(wallet_id);
CREATE INDEX idx_addresses_chain ON addresses(chain);
CREATE INDEX idx_addresses_address ON addresses(address);
CREATE INDEX idx_transactions_wallet_id ON transactions(wallet_id);
CREATE INDEX idx_transactions_tx_hash ON transactions(tx_hash);
CREATE INDEX idx_transactions_status ON transactions(status);
CREATE INDEX idx_transactions_created_at ON transactions(created_at);
CREATE INDEX idx_signatures_wallet_id ON signatures(wallet_id);
CREATE INDEX idx_signatures_message_hash ON signatures(message_hash);
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_wallet_id ON audit_logs(wallet_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);

-- Triggers for updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_wallets_updated_at BEFORE UPDATE ON wallets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_addresses_updated_at BEFORE UPDATE ON addresses
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_transactions_updated_at BEFORE UPDATE ON transactions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_signatures_updated_at BEFORE UPDATE ON signatures
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_api_keys_updated_at BEFORE UPDATE ON api_keys
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Views for common queries
CREATE VIEW wallet_summary AS
SELECT 
    w.id,
    w.wallet_id,
    u.user_id,
    w.created_at,
    w.last_used_at,
    COUNT(a.id) as address_count,
    COUNT(t.id) as transaction_count
FROM wallets w
JOIN users u ON w.user_id = u.id
LEFT JOIN addresses a ON w.id = a.wallet_id AND a.is_active = TRUE
LEFT JOIN transactions t ON w.id = t.wallet_id
GROUP BY w.id, w.wallet_id, u.user_id, w.created_at, w.last_used_at;

-- Insert initial data (optional)
INSERT INTO users (user_id, email) VALUES 
('system', 'system@phillet.io'),
('demo_user', 'demo@phillet.io')
ON CONFLICT (user_id) DO NOTHING; 