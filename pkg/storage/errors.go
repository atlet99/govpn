package storage

import "errors"

var (
	// ErrNotFound is returned when a requested resource is not found
	ErrNotFound = errors.New("resource not found")

	// ErrDuplicateKey is returned when attempting to create a resource with a duplicate unique key
	ErrDuplicateKey = errors.New("duplicate key violation")

	// ErrInvalidInput is returned when input validation fails
	ErrInvalidInput = errors.New("invalid input")

	// ErrTransactionFailed is returned when a database transaction fails
	ErrTransactionFailed = errors.New("transaction failed")

	// ErrConnectionFailed is returned when database connection fails
	ErrConnectionFailed = errors.New("database connection failed")
)
