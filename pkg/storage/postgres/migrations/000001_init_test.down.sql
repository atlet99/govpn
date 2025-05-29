-- Drop triggers
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_certificates_updated_at ON certificates;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop indexes
DROP INDEX IF EXISTS idx_connections_last_activity;
DROP INDEX IF EXISTS idx_connections_username;
DROP INDEX IF EXISTS idx_connections_client_id;
DROP INDEX IF EXISTS idx_certificates_type;
DROP INDEX IF EXISTS idx_certificates_serial;
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_users_username;

-- Drop tables
DROP TABLE IF EXISTS connections;
DROP TABLE IF EXISTS certificates;
DROP TABLE IF EXISTS users;

-- Drop extension
DROP EXTENSION IF EXISTS "uuid-ossp"; 