-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create users table with improved constraints and defaults
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT users_username_length CHECK (char_length(username) >= 3),
    CONSTRAINT users_email_valid CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT users_role_valid CHECK (role IN ('admin', 'user')),
    CONSTRAINT users_status_valid CHECK (status IN ('active', 'inactive', 'suspended'))
);

-- Create certificates table with improved constraints
CREATE TABLE IF NOT EXISTS certificates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type VARCHAR(50) NOT NULL,
    common_name VARCHAR(255) NOT NULL,
    serial VARCHAR(255) NOT NULL,
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    revoke_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT certificates_type_valid CHECK (type IN ('client', 'server', 'ca')),
    CONSTRAINT certificates_serial_unique UNIQUE (serial),
    CONSTRAINT certificates_valid_dates CHECK (not_before < not_after),
    CONSTRAINT certificates_revoked_check CHECK (
        (revoked = FALSE AND revoked_at IS NULL AND revoke_reason IS NULL) OR
        (revoked = TRUE AND revoked_at IS NOT NULL)
    )
);

-- Create connections table with improved constraints
CREATE TABLE IF NOT EXISTS connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    virtual_ip INET NOT NULL,
    bytes_in BIGINT NOT NULL DEFAULT 0,
    bytes_out BIGINT NOT NULL DEFAULT 0,
    connected_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    obfuscation VARCHAR(50),
    protocol VARCHAR(50) NOT NULL,
    client_version VARCHAR(50) NOT NULL,
    CONSTRAINT connections_protocol_valid CHECK (protocol IN ('udp', 'tcp')),
    CONSTRAINT connections_obfuscation_valid CHECK (obfuscation IN ('none', 'obfs4', 'meek')),
    CONSTRAINT connections_username_fk FOREIGN KEY (username) 
        REFERENCES users(username) ON DELETE CASCADE
);

-- Create indexes with improved naming and options (with IF NOT EXISTS workaround)
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_users_username') THEN
        CREATE INDEX idx_users_username ON users(username) INCLUDE (email, role, status);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_users_email') THEN
        CREATE INDEX idx_users_email ON users(email) INCLUDE (username, status);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_certificates_serial') THEN
        CREATE INDEX idx_certificates_serial ON certificates(serial) INCLUDE (type, common_name);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_certificates_type') THEN
        CREATE INDEX idx_certificates_type ON certificates(type) INCLUDE (common_name, serial);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_connections_client_id') THEN
        CREATE INDEX idx_connections_client_id ON connections(client_id) INCLUDE (username, ip_address);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_connections_username') THEN
        CREATE INDEX idx_connections_username ON connections(username) INCLUDE (client_id, last_activity);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_connections_last_activity') THEN
        CREATE INDEX idx_connections_last_activity ON connections(last_activity DESC) INCLUDE (username, client_id);
    END IF;
END $$;

-- Create function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updating updated_at (with IF NOT EXISTS workaround)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_users_updated_at') THEN
        CREATE TRIGGER update_users_updated_at
            BEFORE UPDATE ON users
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_certificates_updated_at') THEN
        CREATE TRIGGER update_certificates_updated_at
            BEFORE UPDATE ON certificates
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;

-- Add comment to tables
COMMENT ON TABLE users IS 'Stores user account information';
COMMENT ON TABLE certificates IS 'Stores SSL/TLS certificates';
COMMENT ON TABLE connections IS 'Stores active VPN connections';

-- Add comments to columns
COMMENT ON COLUMN users.username IS 'Unique username for authentication';
COMMENT ON COLUMN users.email IS 'User email address';
COMMENT ON COLUMN users.role IS 'User role (admin or user)';
COMMENT ON COLUMN users.status IS 'User account status';
COMMENT ON COLUMN certificates.type IS 'Certificate type (client, server, or ca)';
COMMENT ON COLUMN certificates.serial IS 'Unique certificate serial number';
COMMENT ON COLUMN connections.ip_address IS 'Client IP address';
COMMENT ON COLUMN connections.virtual_ip IS 'Assigned VPN IP address'; 