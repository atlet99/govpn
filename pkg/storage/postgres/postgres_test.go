package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/atlet99/govpn/pkg/storage"
)

func setupTestDB(t *testing.T) *PostgresStorage {
	cfg := &storage.Config{
		Host:     "localhost",
		Port:     5432,
		User:     "postgres",
		Password: "postgres",
		Database: "govpn_test",
		SSLMode:  "disable",
		MaxConns: 10,
		MinConns: 1,
	}

	store, err := New(cfg)
	require.NoError(t, err)

	// Clean up the database before each test
	_, err = store.pool.Exec(context.Background(), `
		TRUNCATE users, certificates, connections CASCADE;
	`)
	require.NoError(t, err)

	return store
}

func TestUserOperations(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	// Test CreateUser
	user := &storage.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
		Role:     "user",
		Status:   "active",
	}

	err := store.CreateUser(ctx, user)
	require.NoError(t, err)
	assert.NotEmpty(t, user.ID)
	assert.NotZero(t, user.CreatedAt)
	assert.NotZero(t, user.UpdatedAt)

	// Test GetUser
	retrievedUser, err := store.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.ID, retrievedUser.ID)
	assert.Equal(t, user.Username, retrievedUser.Username)
	assert.Equal(t, user.Email, retrievedUser.Email)
	assert.Equal(t, user.Password, retrievedUser.Password)
	assert.Equal(t, user.Role, retrievedUser.Role)
	assert.Equal(t, user.Status, retrievedUser.Status)

	// Test GetUserByUsername
	retrievedUser, err = store.GetUserByUsername(ctx, user.Username)
	require.NoError(t, err)
	assert.Equal(t, user.ID, retrievedUser.ID)

	// Test UpdateUser
	user.Status = "inactive"
	err = store.UpdateUser(ctx, user)
	require.NoError(t, err)

	retrievedUser, err = store.GetUser(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, "inactive", retrievedUser.Status)

	// Test ListUsers
	users, err := store.ListUsers(ctx, 0, 10)
	require.NoError(t, err)
	assert.Len(t, users, 1)

	// Test CountUsers
	count, err := store.CountUsers(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Test DeleteUser
	err = store.DeleteUser(ctx, user.ID)
	require.NoError(t, err)

	_, err = store.GetUser(ctx, user.ID)
	assert.Equal(t, storage.ErrNotFound, err)
}

func TestCertificateOperations(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	// Test CreateCertificate
	cert := &storage.Certificate{
		Type:       "client",
		CommonName: "test.example.com",
		Serial:     "123456789",
		NotBefore:  time.Now(),
		NotAfter:   time.Now().Add(24 * time.Hour),
	}

	err := store.CreateCertificate(ctx, cert)
	require.NoError(t, err)
	assert.NotEmpty(t, cert.ID)
	assert.NotZero(t, cert.CreatedAt)
	assert.NotZero(t, cert.UpdatedAt)

	// Test GetCertificate
	retrievedCert, err := store.GetCertificate(ctx, cert.ID)
	require.NoError(t, err)
	assert.Equal(t, cert.ID, retrievedCert.ID)
	assert.Equal(t, cert.Type, retrievedCert.Type)
	assert.Equal(t, cert.CommonName, retrievedCert.CommonName)
	assert.Equal(t, cert.Serial, retrievedCert.Serial)

	// Test GetCertificateBySerial
	retrievedCert, err = store.GetCertificateBySerial(ctx, cert.Serial)
	require.NoError(t, err)
	assert.Equal(t, cert.ID, retrievedCert.ID)

	// Test UpdateCertificate
	cert.CommonName = "updated.example.com"
	err = store.UpdateCertificate(ctx, cert)
	require.NoError(t, err)

	retrievedCert, err = store.GetCertificate(ctx, cert.ID)
	require.NoError(t, err)
	assert.Equal(t, "updated.example.com", retrievedCert.CommonName)

	// Test RevokeCertificate
	err = store.RevokeCertificate(ctx, cert.ID, "test revocation")
	require.NoError(t, err)

	retrievedCert, err = store.GetCertificate(ctx, cert.ID)
	require.NoError(t, err)
	assert.True(t, retrievedCert.Revoked)
	assert.NotZero(t, retrievedCert.RevokedAt)
	assert.Equal(t, "test revocation", retrievedCert.RevokeReason.String)

	// Test ListCertificates
	certs, err := store.ListCertificates(ctx, "client", 0, 10)
	require.NoError(t, err)
	assert.Len(t, certs, 1)

	// Test CountCertificates
	count, err := store.CountCertificates(ctx, "client")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestConnectionOperations(t *testing.T) {
	store := setupTestDB(t)
	ctx := context.Background()

	// Create a test user first
	user := &storage.User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password123",
		Role:     "user",
		Status:   "active",
	}
	err := store.CreateUser(ctx, user)
	require.NoError(t, err)

	// Test CreateConnection
	conn := &storage.Connection{
		ClientID:      "test-client",
		Username:      user.Username,
		IPAddress:     "192.168.1.1",
		VirtualIP:     "10.0.0.1",
		Obfuscation:   "none",
		Protocol:      "udp",
		ClientVersion: "1.0.0",
	}

	err = store.CreateConnection(ctx, conn)
	require.NoError(t, err)
	assert.NotEmpty(t, conn.ID)
	assert.NotZero(t, conn.ConnectedAt)
	assert.NotZero(t, conn.LastActivity)

	// Test GetConnection
	retrievedConn, err := store.GetConnection(ctx, conn.ID)
	require.NoError(t, err)
	assert.Equal(t, conn.ID, retrievedConn.ID)
	assert.Equal(t, conn.ClientID, retrievedConn.ClientID)
	assert.Equal(t, conn.Username, retrievedConn.Username)
	assert.Equal(t, conn.IPAddress, retrievedConn.IPAddress)
	assert.Equal(t, conn.VirtualIP, retrievedConn.VirtualIP)

	// Test UpdateConnection
	conn.IPAddress = "192.168.1.2"
	err = store.UpdateConnection(ctx, conn)
	require.NoError(t, err)

	retrievedConn, err = store.GetConnection(ctx, conn.ID)
	require.NoError(t, err)
	assert.Equal(t, "192.168.1.2", retrievedConn.IPAddress)

	// Test UpdateConnectionStats
	err = store.UpdateConnectionStats(ctx, conn.ID, 1000, 2000)
	require.NoError(t, err)

	retrievedConn, err = store.GetConnection(ctx, conn.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1000), retrievedConn.BytesIn)
	assert.Equal(t, int64(2000), retrievedConn.BytesOut)

	// Test ListConnections
	conns, err := store.ListConnections(ctx, 0, 10)
	require.NoError(t, err)
	assert.Len(t, conns, 1)

	// Test CountConnections
	count, err := store.CountConnections(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Test DeleteConnection
	err = store.DeleteConnection(ctx, conn.ID)
	require.NoError(t, err)

	_, err = store.GetConnection(ctx, conn.ID)
	assert.Equal(t, storage.ErrNotFound, err)
}
