// Package storage provides interfaces and implementations for data persistence
package storage

import (
	"context"
	"database/sql"
	"time"
)

// User represents a system user
type User struct {
	ID        string       `json:"id"`
	Username  string       `json:"username"`
	Email     string       `json:"email"`
	Password  string       `json:"-"` // Never expose password in JSON
	Role      string       `json:"role"`
	Status    string       `json:"status"`
	LastLogin sql.NullTime `json:"last_login"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
}

// Certificate represents a TLS certificate
type Certificate struct {
	ID           string         `json:"id"`
	Type         string         `json:"type"` // ca, server, client
	CommonName   string         `json:"common_name"`
	Serial       string         `json:"serial"`
	NotBefore    time.Time      `json:"not_before"`
	NotAfter     time.Time      `json:"not_after"`
	Revoked      bool           `json:"revoked"`
	RevokedAt    sql.NullTime   `json:"revoked_at,omitempty"`
	RevokeReason sql.NullString `json:"revoke_reason,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

// Connection represents an active VPN connection
type Connection struct {
	ID            string    `json:"id"`
	ClientID      string    `json:"client_id"`
	Username      string    `json:"username"`
	IPAddress     string    `json:"ip_address"` // INET, приводить к тексту в SQL
	VirtualIP     string    `json:"virtual_ip"` // INET, приводить к тексту в SQL
	BytesIn       int64     `json:"bytes_in"`
	BytesOut      int64     `json:"bytes_out"`
	ConnectedAt   time.Time `json:"connected_at"`
	LastActivity  time.Time `json:"last_activity"`
	Obfuscation   string    `json:"obfuscation,omitempty"`
	Protocol      string    `json:"protocol"`
	ClientVersion string    `json:"client_version"`
}

// Storage defines the interface for data persistence
type Storage interface {
	// User operations
	CreateUser(ctx context.Context, user *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, offset, limit int) ([]*User, error)
	CountUsers(ctx context.Context) (int, error)

	// Certificate operations
	CreateCertificate(ctx context.Context, cert *Certificate) error
	GetCertificate(ctx context.Context, id string) (*Certificate, error)
	GetCertificateBySerial(ctx context.Context, serial string) (*Certificate, error)
	UpdateCertificate(ctx context.Context, cert *Certificate) error
	RevokeCertificate(ctx context.Context, id, reason string) error
	ListCertificates(ctx context.Context, certType string, offset, limit int) ([]*Certificate, error)
	CountCertificates(ctx context.Context, certType string) (int, error)

	// Connection operations
	CreateConnection(ctx context.Context, conn *Connection) error
	GetConnection(ctx context.Context, id string) (*Connection, error)
	UpdateConnection(ctx context.Context, conn *Connection) error
	DeleteConnection(ctx context.Context, id string) error
	ListConnections(ctx context.Context, offset, limit int) ([]*Connection, error)
	CountConnections(ctx context.Context) (int, error)
	UpdateConnectionStats(ctx context.Context, id string, bytesIn, bytesOut int64) error

	// Transaction support
	BeginTx(ctx context.Context) (Transaction, error)
}

// Transaction represents a database transaction
type Transaction interface {
	Commit() error
	Rollback() error
	Storage
}

// Config holds database configuration
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	SSLMode  string
	MaxConns int
	MinConns int
}
