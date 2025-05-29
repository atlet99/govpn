-- Create users table
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Create certificates table
CREATE TABLE certificates (
    id UUID PRIMARY KEY,
    type VARCHAR(50) NOT NULL,
    common_name VARCHAR(255) NOT NULL,
    serial VARCHAR(255) NOT NULL UNIQUE,
    not_before TIMESTAMP WITH TIME ZONE NOT NULL,
    not_after TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoke_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Create connections table
CREATE TABLE connections (
    id UUID PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    virtual_ip VARCHAR(45) NOT NULL,
    bytes_in BIGINT NOT NULL DEFAULT 0,
    bytes_out BIGINT NOT NULL DEFAULT 0,
    connected_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity TIMESTAMP WITH TIME ZONE NOT NULL,
    obfuscation VARCHAR(50),
    protocol VARCHAR(50) NOT NULL,
    client_version VARCHAR(50) NOT NULL,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- Create indexes
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_certificates_serial ON certificates(serial);
CREATE INDEX idx_certificates_type ON certificates(type);
CREATE INDEX idx_connections_client_id ON connections(client_id);
CREATE INDEX idx_connections_username ON connections(username);
CREATE INDEX idx_connections_last_activity ON connections(last_activity); 