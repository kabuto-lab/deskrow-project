package keystore

// KeyStorage defines the interface for storing and retrieving
// cryptographic keys and secrets required by the application.
// Implementations of this interface handle the actual persistence
// (e.g., to a database, file system, or secrets manager).
type KeyStorage interface {
	// StoreKey stores an encryption key associated with a version.
	// operationID can be used to link the key storage to a rotation event.
	StoreKey(version int, key []byte, operationID string) error

	// LoadKeys retrieves all active encryption keys, keyed by their version.
	LoadKeys() (map[int][]byte, error)

	// StoreSessionSecret stores a secret used for signing session tokens.
	StoreSessionSecret(version int, secret string, operationID string) error

	// LoadSessionSecrets retrieves all active session secrets, keyed by version.
	LoadSessionSecrets() (map[int]string, error)

	// StoreCSRFSecret stores a secret used for CSRF protection.
	StoreCSRFSecret(version int, secret string, operationID string) error

	// LoadCSRFSecrets retrieves all active CSRF secrets, keyed by version.
	LoadCSRFSecrets() (map[int]string, error)

	// StoreServerFingerprint stores the fingerprint of a server's public key
	StoreServerFingerprint(fingerprint string) error

	// LoadServerFingerprint retrieves the stored server fingerprint
	LoadServerFingerprint() (string, error)
}
