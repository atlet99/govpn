#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored messages
print_message() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Function to check if a command exists
check_command() {
    if ! command -v "$1" &> /dev/null; then
        print_message "$RED" "Error: $1 is not installed"
        print_message "$YELLOW" "Please install $1 to run the tests"
        exit 1
    fi
}

# Function to check PostgreSQL connection
check_postgres_connection() {
    # Try to connect with different methods
    if ! psql -U postgres -c "SELECT 1" &> /dev/null; then
        print_message "$RED" "Error: Cannot connect to PostgreSQL"
        print_message "$YELLOW" "Trying to connect with different methods..."
        
        # Try with socket
        if ! psql -h localhost -U postgres -c "SELECT 1" &> /dev/null; then
            print_message "$RED" "Failed to connect using socket"
        else
            print_message "$GREEN" "Successfully connected using socket"
            return 0
        fi
        
        # Try with default port
        if ! psql -h localhost -p 5432 -U postgres -c "SELECT 1" &> /dev/null; then
            print_message "$RED" "Failed to connect using default port"
        else
            print_message "$GREEN" "Successfully connected using default port"
            return 0
        fi
        
        print_message "$YELLOW" "Please check the following:"
        print_message "$YELLOW" "1. Is PostgreSQL running? Try:"
        print_message "$YELLOW" "   - On macOS: brew services list"
        print_message "$YELLOW" "   - On Linux: systemctl status postgresql"
        print_message "$YELLOW" "   - On Windows: Check Services app"
        
        print_message "$YELLOW" "2. Is the postgres user password set? Try:"
        print_message "$YELLOW" "   export PGPASSWORD=your_password"
        
        print_message "$YELLOW" "3. Is pg_hba.conf configured correctly? Check:"
        print_message "$YELLOW" "   - On macOS: /usr/local/var/postgres/pg_hba.conf"
        print_message "$YELLOW" "   - On Linux: /etc/postgresql/15/main/pg_hba.conf"
        print_message "$YELLOW" "   - On Windows: C:\\Program Files\\PostgreSQL\\15\\data\\pg_hba.conf"
        
        print_message "$YELLOW" "4. Try connecting manually:"
        print_message "$YELLOW" "   psql -U postgres"
        
        exit 1
    fi
}

# Function to check PostgreSQL version
check_postgres_version() {
    local version
    version=$(psql -U postgres -t -c "SHOW server_version_num;" | tr -d ' ')
    
    if [ -z "$version" ]; then
        print_message "$RED" "Error: Could not determine PostgreSQL version"
        exit 1
    fi

    # PostgreSQL 15 version number is 150000
    if [ "$version" -lt 150000 ]; then
        print_message "$RED" "Error: PostgreSQL version 15 or higher is required"
        print_message "$YELLOW" "Current version: $(psql -U postgres -t -c "SHOW server_version;")"
        print_message "$YELLOW" "Please upgrade your PostgreSQL installation"
        exit 1
    fi

    print_message "$GREEN" "PostgreSQL version check passed: $(psql -U postgres -t -c "SHOW server_version;")"
}

# Function to handle errors
handle_error() {
    local exit_code=$1
    local error_message=$2
    if [ $exit_code -ne 0 ]; then
        print_message "$RED" "Error: $error_message"
        exit $exit_code
    fi
}

# Check required commands
print_message "$YELLOW" "Checking dependencies..."
check_command "psql"
check_command "go"

# Set environment variables
export PGPASSWORD=${PGPASSWORD:-"postgres"}
export TEST_DB_HOST=${TEST_DB_HOST:-"localhost"}
export TEST_DB_PORT=${TEST_DB_PORT:-"5432"}
export TEST_DB_USER=${TEST_DB_USER:-"postgres"}
export TEST_DB_PASSWORD=${TEST_DB_PASSWORD:-"postgres"}
export TEST_DB_NAME=${TEST_DB_NAME:-"govpn_test"}

# Check PostgreSQL connection
print_message "$YELLOW" "Checking PostgreSQL connection..."
check_postgres_connection

# Check PostgreSQL version
print_message "$YELLOW" "Checking PostgreSQL version..."
check_postgres_version

# Create test database
print_message "$YELLOW" "Creating test database..."
psql -U postgres -c "DROP DATABASE IF EXISTS $TEST_DB_NAME;" 2>/dev/null || true
psql -U postgres -c "CREATE DATABASE $TEST_DB_NAME;"
handle_error $? "Failed to create test database"

# Run migrations
print_message "$YELLOW" "Running database migrations..."
psql -U postgres -d "$TEST_DB_NAME" -f pkg/storage/postgres/migrations/000001_init_test.up.sql
handle_error $? "Failed to run migrations"

# Run tests
print_message "$YELLOW" "Running tests..."
go test -v ./pkg/storage/postgres/...
test_exit_code=$?

# Clean up
print_message "$YELLOW" "Cleaning up..."
psql -U postgres -c "DROP DATABASE IF EXISTS $TEST_DB_NAME;" 2>/dev/null || true

# Print summary
if [ $test_exit_code -eq 0 ]; then
    print_message "$GREEN" "All tests completed successfully!"
else
    print_message "$RED" "Some tests failed!"
fi

exit $test_exit_code 