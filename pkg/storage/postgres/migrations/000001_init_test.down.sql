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