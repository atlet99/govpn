// Package postgres provides PostgreSQL implementation of the storage interface
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/atlet99/govpn/pkg/storage"
)

// PostgresStorage implements the storage.Storage interface using PostgreSQL
type PostgresStorage struct {
	pool *pgxpool.Pool
}

// New creates a new PostgreSQL storage instance
func New(cfg *storage.Config) (*PostgresStorage, error) {
	connString := formatConnString(cfg)
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		return nil, err
	}

	return &PostgresStorage{pool: pool}, nil
}

// formatConnString formats the connection string from config
func formatConnString(cfg *storage.Config) string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s pool_max_conns=%d pool_min_conns=%d",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.Database, cfg.SSLMode,
		cfg.MaxConns, cfg.MinConns,
	)
}

// Close closes the database connection pool
func (s *PostgresStorage) Close() error {
	s.pool.Close()
	return nil
}

// BeginTx starts a new transaction
func (s *PostgresStorage) BeginTx(ctx context.Context) (storage.Transaction, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return &PostgresTransaction{tx: tx}, nil
}

// PostgresTransaction implements the storage.Transaction interface
type PostgresTransaction struct {
	tx pgx.Tx
}

func (t *PostgresTransaction) Commit() error {
	return t.tx.Commit(context.Background())
}

func (t *PostgresTransaction) Rollback() error {
	return t.tx.Rollback(context.Background())
}

// BeginTx starts a new nested transaction
func (t *PostgresTransaction) BeginTx(ctx context.Context) (storage.Transaction, error) {
	// PostgreSQL doesn't support nested transactions, so we'll just return the current transaction
	return t, nil
}

// CountCertificates returns the number of certificates of the specified type
func (t *PostgresTransaction) CountCertificates(ctx context.Context, certType string) (int, error) {
	var count int
	err := t.tx.QueryRow(ctx, "SELECT COUNT(*) FROM certificates WHERE type = $1", certType).Scan(&count)
	return count, err
}

// CountConnections returns the total number of connections
func (t *PostgresTransaction) CountConnections(ctx context.Context) (int, error) {
	var count int
	err := t.tx.QueryRow(ctx, "SELECT COUNT(*) FROM connections").Scan(&count)
	return count, err
}

// CountUsers returns the total number of users
func (t *PostgresTransaction) CountUsers(ctx context.Context) (int, error) {
	var count int
	err := t.tx.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

// CreateUser creates a new user
func (t *PostgresTransaction) CreateUser(ctx context.Context, user *storage.User) error {
	query := `
		INSERT INTO users (id, username, email, password, role, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	user.ID = uuid.New().String()
	user.CreatedAt = time.Now()
	user.UpdatedAt = user.CreatedAt

	_, err := t.tx.Exec(ctx, query,
		user.ID, user.Username, user.Email, user.Password,
		user.Role, user.Status, user.CreatedAt, user.UpdatedAt,
	)
	return err
}

// GetUser retrieves a user by ID
func (t *PostgresTransaction) GetUser(ctx context.Context, id string) (*storage.User, error) {
	query := `
		SELECT id, username, email, password, role, status, last_login, created_at, updated_at
		FROM users WHERE id = $1
	`
	var user storage.User
	err := t.tx.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.Password,
		&user.Role, &user.Status, &user.LastLogin,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, storage.ErrNotFound
	}
	return &user, err
}

// GetUserByUsername retrieves a user by username
func (t *PostgresTransaction) GetUserByUsername(ctx context.Context, username string) (*storage.User, error) {
	query := `
		SELECT id, username, email, password, role, status, last_login, created_at, updated_at
		FROM users WHERE username = $1
	`
	var user storage.User
	err := t.tx.QueryRow(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.Password,
		&user.Role, &user.Status, &user.LastLogin,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, storage.ErrNotFound
	}
	return &user, err
}

// UpdateUser updates an existing user
func (t *PostgresTransaction) UpdateUser(ctx context.Context, user *storage.User) error {
	query := `
		UPDATE users
		SET username = $1, email = $2, password = $3, role = $4, status = $5, updated_at = $6
		WHERE id = $7
	`
	user.UpdatedAt = time.Now()
	_, err := t.tx.Exec(ctx, query,
		user.Username, user.Email, user.Password,
		user.Role, user.Status, user.UpdatedAt, user.ID,
	)
	return err
}

// DeleteUser deletes a user by ID
func (t *PostgresTransaction) DeleteUser(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE id = $1`
	_, err := t.tx.Exec(ctx, query, id)
	return err
}

// ListUsers retrieves a list of users with pagination
func (t *PostgresTransaction) ListUsers(ctx context.Context, offset, limit int) ([]*storage.User, error) {
	query := `
		SELECT id, username, email, password, role, status, last_login, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`
	rows, err := t.tx.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*storage.User
	for rows.Next() {
		var user storage.User
		err := rows.Scan(
			&user.ID, &user.Username, &user.Email, &user.Password,
			&user.Role, &user.Status, &user.LastLogin,
			&user.CreatedAt, &user.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, &user)
	}
	return users, rows.Err()
}

// CreateCertificate creates a new certificate
func (t *PostgresTransaction) CreateCertificate(ctx context.Context, cert *storage.Certificate) error {
	query := `
		INSERT INTO certificates (id, type, common_name, serial, not_before, not_after, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	cert.ID = uuid.New().String()
	cert.CreatedAt = time.Now()
	cert.UpdatedAt = cert.CreatedAt

	_, err := t.tx.Exec(ctx, query,
		cert.ID, cert.Type, cert.CommonName, cert.Serial,
		cert.NotBefore, cert.NotAfter, cert.CreatedAt, cert.UpdatedAt,
	)
	return err
}

// GetCertificate retrieves a certificate by ID
func (t *PostgresTransaction) GetCertificate(ctx context.Context, id string) (*storage.Certificate, error) {
	query := `
		SELECT id, type, common_name, serial, not_before, not_after, revoked, revoked_at, revoke_reason, created_at, updated_at
		FROM certificates WHERE id = $1
	`
	var cert storage.Certificate
	var revokeReason sql.NullString
	err := t.tx.QueryRow(ctx, query, id).Scan(
		&cert.ID, &cert.Type, &cert.CommonName, &cert.Serial,
		&cert.NotBefore, &cert.NotAfter, &cert.Revoked,
		&cert.RevokedAt, &revokeReason,
		&cert.CreatedAt, &cert.UpdatedAt,
	)
	cert.RevokeReason = revokeReason
	if err == pgx.ErrNoRows {
		return nil, storage.ErrNotFound
	}
	return &cert, err
}

// GetCertificateBySerial retrieves a certificate by serial number
func (t *PostgresTransaction) GetCertificateBySerial(ctx context.Context, serial string) (*storage.Certificate, error) {
	query := `
		SELECT id, type, common_name, serial, not_before, not_after, revoked, revoked_at, revoke_reason, created_at, updated_at
		FROM certificates WHERE serial = $1
	`
	var cert storage.Certificate
	var revokeReason sql.NullString
	err := t.tx.QueryRow(ctx, query, serial).Scan(
		&cert.ID, &cert.Type, &cert.CommonName, &cert.Serial,
		&cert.NotBefore, &cert.NotAfter, &cert.Revoked,
		&cert.RevokedAt, &revokeReason,
		&cert.CreatedAt, &cert.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	cert.RevokeReason = revokeReason
	return &cert, nil
}

// UpdateCertificate updates an existing certificate
func (t *PostgresTransaction) UpdateCertificate(ctx context.Context, cert *storage.Certificate) error {
	query := `
		UPDATE certificates
		SET type = $1, common_name = $2, serial = $3, not_before = $4, not_after = $5,
			revoked = $6, revoked_at = $7, revoke_reason = $8, updated_at = $9
		WHERE id = $10
	`
	cert.UpdatedAt = time.Now()
	_, err := t.tx.Exec(ctx, query,
		cert.Type, cert.CommonName, cert.Serial,
		cert.NotBefore, cert.NotAfter, cert.Revoked,
		cert.RevokedAt, cert.RevokeReason, cert.UpdatedAt,
		cert.ID,
	)
	return err
}

// RevokeCertificate revokes a certificate
func (t *PostgresTransaction) RevokeCertificate(ctx context.Context, id, reason string) error {
	query := `
		UPDATE certificates
		SET revoked = true, revoked_at = $1, revoke_reason = $2, updated_at = $3
		WHERE id = $4
	`
	now := time.Now()
	_, err := t.tx.Exec(ctx, query, now, reason, now, id)
	return err
}

// ListCertificates retrieves a list of certificates with pagination
func (t *PostgresTransaction) ListCertificates(ctx context.Context, certType string, offset, limit int) ([]*storage.Certificate, error) {
	query := `
		SELECT id, type, common_name, serial, not_before, not_after, revoked, revoked_at, revoke_reason, created_at, updated_at
		FROM certificates
		WHERE type = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := t.tx.Query(ctx, query, certType, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []*storage.Certificate
	for rows.Next() {
		var cert storage.Certificate
		err := rows.Scan(
			&cert.ID, &cert.Type, &cert.CommonName, &cert.Serial,
			&cert.NotBefore, &cert.NotAfter, &cert.Revoked,
			&cert.RevokedAt, &cert.RevokeReason,
			&cert.CreatedAt, &cert.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		certs = append(certs, &cert)
	}
	return certs, rows.Err()
}

// CreateConnection creates a new connection
func (t *PostgresTransaction) CreateConnection(ctx context.Context, conn *storage.Connection) error {
	query := `
		INSERT INTO connections (id, client_id, username, ip_address, virtual_ip, connected_at, last_activity, obfuscation, protocol, client_version)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	conn.ID = uuid.New().String()
	conn.ConnectedAt = time.Now()
	conn.LastActivity = conn.ConnectedAt

	_, err := t.tx.Exec(ctx, query,
		conn.ID, conn.ClientID, conn.Username, conn.IPAddress,
		conn.VirtualIP, conn.ConnectedAt, conn.LastActivity,
		conn.Obfuscation, conn.Protocol, conn.ClientVersion,
	)
	return err
}

// GetConnection retrieves a connection by ID
func (t *PostgresTransaction) GetConnection(ctx context.Context, id string) (*storage.Connection, error) {
	query := `
		SELECT id, client_id, username, host(ip_address), host(virtual_ip), bytes_in, bytes_out,
			connected_at, last_activity, obfuscation, protocol, client_version
		FROM connections WHERE id = $1
	`
	var conn storage.Connection
	err := t.tx.QueryRow(ctx, query, id).Scan(
		&conn.ID, &conn.ClientID, &conn.Username, &conn.IPAddress,
		&conn.VirtualIP, &conn.BytesIn, &conn.BytesOut,
		&conn.ConnectedAt, &conn.LastActivity,
		&conn.Obfuscation, &conn.Protocol, &conn.ClientVersion,
	)
	if err == pgx.ErrNoRows {
		return nil, storage.ErrNotFound
	}
	return &conn, err
}

// UpdateConnection updates an existing connection
func (t *PostgresTransaction) UpdateConnection(ctx context.Context, conn *storage.Connection) error {
	query := `
		UPDATE connections
		SET client_id = $1, username = $2, ip_address = $3, virtual_ip = $4,
			bytes_in = $5, bytes_out = $6, last_activity = $7,
			obfuscation = $8, protocol = $9, client_version = $10
		WHERE id = $11
	`
	conn.LastActivity = time.Now()
	_, err := t.tx.Exec(ctx, query,
		conn.ClientID, conn.Username, conn.IPAddress,
		conn.VirtualIP, conn.BytesIn, conn.BytesOut,
		conn.LastActivity, conn.Obfuscation,
		conn.Protocol, conn.ClientVersion, conn.ID,
	)
	return err
}

// DeleteConnection deletes a connection by ID
func (t *PostgresTransaction) DeleteConnection(ctx context.Context, id string) error {
	query := `DELETE FROM connections WHERE id = $1`
	_, err := t.tx.Exec(ctx, query, id)
	return err
}

// ListConnections retrieves a list of connections with pagination
func (t *PostgresTransaction) ListConnections(ctx context.Context, offset, limit int) ([]*storage.Connection, error) {
	query := `
		SELECT id, client_id, username, host(ip_address), host(virtual_ip), bytes_in, bytes_out,
			connected_at, last_activity, obfuscation, protocol, client_version
		FROM connections
		ORDER BY last_activity DESC
		LIMIT $1 OFFSET $2
	`
	rows, err := t.tx.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var conns []*storage.Connection
	for rows.Next() {
		var conn storage.Connection
		err := rows.Scan(
			&conn.ID, &conn.ClientID, &conn.Username, &conn.IPAddress,
			&conn.VirtualIP, &conn.BytesIn, &conn.BytesOut,
			&conn.ConnectedAt, &conn.LastActivity,
			&conn.Obfuscation, &conn.Protocol, &conn.ClientVersion,
		)
		if err != nil {
			return nil, err
		}
		conns = append(conns, &conn)
	}
	return conns, rows.Err()
}

// UpdateConnectionStats updates connection statistics
func (t *PostgresTransaction) UpdateConnectionStats(ctx context.Context, id string, bytesIn, bytesOut int64) error {
	query := `
		UPDATE connections
		SET bytes_in = bytes_in + $1, bytes_out = bytes_out + $2, last_activity = $3
		WHERE id = $4
	`
	_, err := t.tx.Exec(ctx, query, bytesIn, bytesOut, time.Now(), id)
	return err
}

// Helper functions
func (s *PostgresStorage) withTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// User operations
func (s *PostgresStorage) CreateUser(ctx context.Context, user *storage.User) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		t := &PostgresTransaction{tx: tx}
		return t.CreateUser(ctx, user)
	})
}

func (s *PostgresStorage) GetUser(ctx context.Context, id string) (*storage.User, error) {
	query := `
		SELECT id, username, email, password, role, status, last_login, created_at, updated_at
		FROM users WHERE id = $1
	`
	var user storage.User
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.Password,
		&user.Role, &user.Status, &user.LastLogin,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, storage.ErrNotFound
	}
	return &user, err
}

func (s *PostgresStorage) GetUserByUsername(ctx context.Context, username string) (*storage.User, error) {
	query := `
		SELECT id, username, email, password, role, status, last_login, created_at, updated_at
		FROM users WHERE username = $1
	`
	var user storage.User
	err := s.pool.QueryRow(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.Password,
		&user.Role, &user.Status, &user.LastLogin,
		&user.CreatedAt, &user.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, storage.ErrNotFound
	}
	return &user, err
}

func (s *PostgresStorage) UpdateUser(ctx context.Context, user *storage.User) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		t := &PostgresTransaction{tx: tx}
		return t.UpdateUser(ctx, user)
	})
}

func (s *PostgresStorage) DeleteUser(ctx context.Context, id string) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		t := &PostgresTransaction{tx: tx}
		return t.DeleteUser(ctx, id)
	})
}

func (s *PostgresStorage) ListUsers(ctx context.Context, offset, limit int) ([]*storage.User, error) {
	query := `
		SELECT id, username, email, password, role, status, last_login, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`
	rows, err := s.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*storage.User
	for rows.Next() {
		var user storage.User
		err := rows.Scan(
			&user.ID, &user.Username, &user.Email, &user.Password,
			&user.Role, &user.Status, &user.LastLogin,
			&user.CreatedAt, &user.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, &user)
	}
	return users, rows.Err()
}

func (s *PostgresStorage) CountUsers(ctx context.Context) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM users").Scan(&count)
	return count, err
}

// Certificate operations
func (s *PostgresStorage) CreateCertificate(ctx context.Context, cert *storage.Certificate) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		t := &PostgresTransaction{tx: tx}
		return t.CreateCertificate(ctx, cert)
	})
}

func (s *PostgresStorage) GetCertificate(ctx context.Context, id string) (*storage.Certificate, error) {
	query := `
		SELECT id, type, common_name, serial, not_before, not_after, revoked, revoked_at, revoke_reason, created_at, updated_at
		FROM certificates WHERE id = $1
	`
	var cert storage.Certificate
	var revokeReason sql.NullString
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&cert.ID, &cert.Type, &cert.CommonName, &cert.Serial,
		&cert.NotBefore, &cert.NotAfter, &cert.Revoked,
		&cert.RevokedAt, &revokeReason,
		&cert.CreatedAt, &cert.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	cert.RevokeReason = revokeReason
	return &cert, nil
}

func (s *PostgresStorage) GetCertificateBySerial(ctx context.Context, serial string) (*storage.Certificate, error) {
	query := `
		SELECT id, type, common_name, serial, not_before, not_after, revoked, revoked_at, revoke_reason, created_at, updated_at
		FROM certificates WHERE serial = $1
	`
	var cert storage.Certificate
	var revokeReason sql.NullString
	err := s.pool.QueryRow(ctx, query, serial).Scan(
		&cert.ID, &cert.Type, &cert.CommonName, &cert.Serial,
		&cert.NotBefore, &cert.NotAfter, &cert.Revoked,
		&cert.RevokedAt, &revokeReason,
		&cert.CreatedAt, &cert.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, storage.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	cert.RevokeReason = revokeReason
	return &cert, nil
}

func (s *PostgresStorage) UpdateCertificate(ctx context.Context, cert *storage.Certificate) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		t := &PostgresTransaction{tx: tx}
		return t.UpdateCertificate(ctx, cert)
	})
}

func (s *PostgresStorage) RevokeCertificate(ctx context.Context, id, reason string) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		t := &PostgresTransaction{tx: tx}
		return t.RevokeCertificate(ctx, id, reason)
	})
}

func (s *PostgresStorage) ListCertificates(ctx context.Context, certType string, offset, limit int) ([]*storage.Certificate, error) {
	query := `
		SELECT id, type, common_name, serial, not_before, not_after, revoked, revoked_at, revoke_reason, created_at, updated_at
		FROM certificates
		WHERE type = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := s.pool.Query(ctx, query, certType, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var certs []*storage.Certificate
	for rows.Next() {
		var cert storage.Certificate
		err := rows.Scan(
			&cert.ID, &cert.Type, &cert.CommonName, &cert.Serial,
			&cert.NotBefore, &cert.NotAfter, &cert.Revoked,
			&cert.RevokedAt, &cert.RevokeReason,
			&cert.CreatedAt, &cert.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		certs = append(certs, &cert)
	}
	return certs, rows.Err()
}

func (s *PostgresStorage) CountCertificates(ctx context.Context, certType string) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM certificates WHERE type = $1", certType).Scan(&count)
	return count, err
}

// Connection operations
func (s *PostgresStorage) CreateConnection(ctx context.Context, conn *storage.Connection) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		t := &PostgresTransaction{tx: tx}
		return t.CreateConnection(ctx, conn)
	})
}

func (s *PostgresStorage) GetConnection(ctx context.Context, id string) (*storage.Connection, error) {
	query := `
		SELECT id, client_id, username, host(ip_address), host(virtual_ip), bytes_in, bytes_out,
			connected_at, last_activity, obfuscation, protocol, client_version
		FROM connections WHERE id = $1
	`
	var conn storage.Connection
	err := s.pool.QueryRow(ctx, query, id).Scan(
		&conn.ID, &conn.ClientID, &conn.Username, &conn.IPAddress,
		&conn.VirtualIP, &conn.BytesIn, &conn.BytesOut,
		&conn.ConnectedAt, &conn.LastActivity,
		&conn.Obfuscation, &conn.Protocol, &conn.ClientVersion,
	)
	if err == pgx.ErrNoRows {
		return nil, storage.ErrNotFound
	}
	return &conn, err
}

func (s *PostgresStorage) UpdateConnection(ctx context.Context, conn *storage.Connection) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		t := &PostgresTransaction{tx: tx}
		return t.UpdateConnection(ctx, conn)
	})
}

func (s *PostgresStorage) DeleteConnection(ctx context.Context, id string) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		t := &PostgresTransaction{tx: tx}
		return t.DeleteConnection(ctx, id)
	})
}

func (s *PostgresStorage) ListConnections(ctx context.Context, offset, limit int) ([]*storage.Connection, error) {
	query := `
		SELECT id, client_id, username, host(ip_address), host(virtual_ip), bytes_in, bytes_out,
			connected_at, last_activity, obfuscation, protocol, client_version
		FROM connections
		ORDER BY last_activity DESC
		LIMIT $1 OFFSET $2
	`
	rows, err := s.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var conns []*storage.Connection
	for rows.Next() {
		var conn storage.Connection
		err := rows.Scan(
			&conn.ID, &conn.ClientID, &conn.Username, &conn.IPAddress,
			&conn.VirtualIP, &conn.BytesIn, &conn.BytesOut,
			&conn.ConnectedAt, &conn.LastActivity,
			&conn.Obfuscation, &conn.Protocol, &conn.ClientVersion,
		)
		if err != nil {
			return nil, err
		}
		conns = append(conns, &conn)
	}
	return conns, rows.Err()
}

func (s *PostgresStorage) CountConnections(ctx context.Context) (int, error) {
	var count int
	err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM connections").Scan(&count)
	return count, err
}

func (s *PostgresStorage) UpdateConnectionStats(ctx context.Context, id string, bytesIn, bytesOut int64) error {
	return s.withTx(ctx, func(tx pgx.Tx) error {
		t := &PostgresTransaction{tx: tx}
		return t.UpdateConnectionStats(ctx, id, bytesIn, bytesOut)
	})
}
