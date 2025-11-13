package db

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"deskrow/crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID                    int
	UsernameHash          string // Bcrypt hashed username for lookup
	UsernameEncryptedPwd  string // Password-derived encrypted username (for recovery)
	UsernameEncryptedSeed string // Seed-phrase derived encrypted username (for recovery)
	PasswordHash          string // Bcrypt hashed password (optional for wallet users)
	PasswordEncryptedSeed string // Seed-phrase derived encrypted password (for recovery)
	SeedEncrypted         string // Password-derived encrypted seed phrase
	PublicKeyEncrypted    string // Password-derived encrypted public key
	PrivateKeyEncrypted   string // Password-derived encrypted private key
	TwoFASecretEncrypted  string // Password-derived encrypted 2FA secret
	WalletAddress         string // Public key/address from connected wallet
	WalletType            string // Type of wallet (phantom, metamask, etc)
	IsWalletUser          bool   // True if this is a wallet-only user
	KeyVersion            int    // Current encryption key version
	LastRotatedAt         time.Time
	LastReencryptedAt     time.Time
	CreatedAt             time.Time
}

type Identity struct {
	ID                  int
	UserID              int
	PublicKey           string // Derived from user Private key
	PrivateKeyEncrypted string
	Alias               string
	IsDefault           bool
	CreatedAt           time.Time
	Identicon           string     // SVG data for standard 80x80 identicon
	IdenticonSmall      string     // SVG data for small 40x40 identicon
	IsNFT               bool       // True if this is NFT-type Identity
	NFTMintAddress      string     // NFT mint address
	NFTMetadataURI      string     // URI to NFT metadata
	NFTImageURI         string     // URI to identicon image
	NFTMintedAt         *time.Time // When NFT was minted
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func GenerateKeyPair() (publicKey string, privateKey string, err error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	// Encode keys as base64 for storage
	publicKey = base64.StdEncoding.EncodeToString(pubKey)
	privateKey = base64.StdEncoding.EncodeToString(privKey)

	return publicKey, privateKey, nil
}

func GenerateUserAlias() (string, error) {
	// First try to use words.json
	file, err := os.ReadFile("frontend/static/js/words.json")
	if err != nil {
		log.Printf("Warning: Could not read words.json: %v", err)
	} else {
		var words struct {
			Adjectives []string `json:"adjectives"`
			Nouns      []string `json:"nouns"`
		}
		if err := json.Unmarshal(file, &words); err != nil {
			log.Printf("Warning: Could not parse words.json: %v", err)
		} else {
			if len(words.Adjectives) > 0 && len(words.Nouns) > 0 {
				adjIdx, err := rand.Int(rand.Reader, big.NewInt(int64(len(words.Adjectives))))
				if err != nil {
					log.Printf("Warning: Failed to generate adjective index: %v", err)
				} else {
					nounIdx, err := rand.Int(rand.Reader, big.NewInt(int64(len(words.Nouns))))
					if err != nil {
						log.Printf("Warning: Failed to generate noun index: %v", err)
					} else {
						return words.Adjectives[adjIdx.Int64()] + "-" + words.Nouns[nounIdx.Int64()], nil
					}
				}
			}
		}
	}

	// Fallback to simple random string
	const fallbackChars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, 12)
	for i := range result {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(fallbackChars))))
		if err != nil {
			return "", fmt.Errorf("failed to generate random alias: %w", err)
		}
		result[i] = fallbackChars[idx.Int64()]
	}
	return "user-" + string(result), nil
}

func CreateUser(username, passwordHash string, walletAddress, walletType string) (*User, error) {
	// Verify database connection
	if DB == nil {
		return nil, fmt.Errorf("database connection is nil")
	}

	// Check for empty fields
	if username == "" {
		return nil, fmt.Errorf("username is required")
	}

	// Only require password for non-wallet users
	if walletAddress == "" && passwordHash == "" {
		return nil, fmt.Errorf("password is required for standard users")
	}

	// Generate bcrypt hashed username
	usernameHashBytes, err := bcrypt.GenerateFromPassword([]byte(username), 14)
	if err != nil {
		return nil, fmt.Errorf("failed to hash username: %w", err)
	}
	usernameHash := string(usernameHashBytes)

	var usernameToStore string
	if walletAddress != "" {
		// For wallet users, store username unencrypted
		usernameToStore = username
	} else {
		// For standard users, encrypt the username
		usernameToStore, err = crypto.EncryptWithPassword(username, passwordHash, DefaultCryptoAuditLogger, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt username: %w", err)
		}
	}

	// Generate seed phrase if not a wallet user
	var seedEncrypted, publicKeyEncrypted, privateKeyEncrypted, twoFASecretEncrypted string
	if walletAddress == "" {
		// Load word list from words.json
		file, err := os.ReadFile("frontend/static/js/words.json")
		if err != nil {
			return nil, fmt.Errorf("failed to read words.json: %w", err)
		}

		var wordList struct {
			Nouns []string `json:"nouns"`
		}
		if err := json.Unmarshal(file, &wordList); err != nil {
			return nil, fmt.Errorf("failed to parse words.json: %w", err)
		}

		// Generate 12-word seed phrase
		seedPhrase, err := crypto.GenerateSeedPhrase(wordList.Nouns)
		if err != nil {
			return nil, fmt.Errorf("failed to generate seed phrase: %w", err)
		}

		// Encrypt seed with password
		seedEncrypted, err = crypto.EncryptWithPassword(seedPhrase, passwordHash, DefaultCryptoAuditLogger, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt seed: %w", err)
		}

		// Generate deterministic key pair from seed
		publicKey, privateKey, err := crypto.GenerateDeterministicKeyPair(seedPhrase)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key pair: %w", err)
		}

		// Encrypt keys with password
		publicKeyEncrypted, err = crypto.EncryptWithPassword(publicKey, passwordHash, DefaultCryptoAuditLogger, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt public key: %w", err)
		}
		privateKeyEncrypted, err = crypto.EncryptWithPassword(privateKey, passwordHash, DefaultCryptoAuditLogger, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt private key: %w", err)
		}

		// Generate and encrypt 2FA secret
		twoFASecret, err := crypto.GenerateTwoFASecret()
		if err != nil {
			return nil, fmt.Errorf("failed to generate 2FA secret: %w", err)
		}
		twoFASecretEncrypted, err = crypto.EncryptWithPassword(twoFASecret, passwordHash, DefaultCryptoAuditLogger, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt 2FA secret: %w", err)
		}
	}

	result, err := DB.Exec(
		"INSERT INTO users (username_hash, username_encrypted_pwd, username_encrypted_seed, password_hash, password_encrypted_seed, seed_encrypted, public_key_encrypted, private_key_encrypted, two_fa_secret_encrypted, wallet_address, wallet_type, is_wallet_user) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		usernameHash, usernameToStore, "", passwordHash, "", seedEncrypted, publicKeyEncrypted, privateKeyEncrypted, twoFASecretEncrypted, walletAddress, walletType, walletAddress != "",
	)
	if err != nil {
		log.Printf("Database error creating user: %v", err)
		if err.Error() == "UNIQUE constraint failed: users.username_hash" {
			return nil, fmt.Errorf("username already exists")
		}
		return nil, fmt.Errorf("database error: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get last insert ID: %w", err)
	}

	// Return the newly created user with basic fields
	return &User{
		ID:                    int(id),
		UsernameHash:          usernameHash,
		UsernameEncryptedPwd:  usernameToStore,
		UsernameEncryptedSeed: "",
		PasswordHash:          passwordHash,
		PasswordEncryptedSeed: "",
		WalletAddress:         walletAddress,
		WalletType:            walletType,
		IsWalletUser:          walletAddress != "",
		CreatedAt:             time.Now(),
	}, nil
}

func UsernameExists(usernameHash string) (bool, error) {
	var exists bool
	err := DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username_hash = ?)", usernameHash).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check username existence: %w", err)
	}
	return exists, nil
}

func GetUserByID(id int) (*User, error) {
	var user User
	err := DB.QueryRow(
		"SELECT id, username_hash, username_encrypted_pwd, username_encrypted_seed, password_hash, password_encrypted_seed, seed_encrypted, public_key_encrypted, private_key_encrypted, two_fa_secret_encrypted, wallet_address, wallet_type, is_wallet_user, key_version, last_rotated_at, last_reencrypted_at, created_at FROM users WHERE id = ?",
		id,
	).Scan(&user.ID, &user.UsernameHash, &user.UsernameEncryptedPwd, &user.UsernameEncryptedSeed, &user.PasswordHash, &user.PasswordEncryptedSeed, &user.SeedEncrypted, &user.PublicKeyEncrypted, &user.PrivateKeyEncrypted, &user.TwoFASecretEncrypted, &user.WalletAddress, &user.WalletType, &user.IsWalletUser, &user.KeyVersion, &user.LastRotatedAt, &user.LastReencryptedAt, &user.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

func GetUserByUsernameHash(usernameHash string) (*User, error) {
	var user User
	err := DB.QueryRow(
		"SELECT id, username_hash, username_encrypted_pwd, username_encrypted_seed, password_hash, password_encrypted_seed, seed_encrypted, public_key_encrypted, private_key_encrypted, two_fa_secret_encrypted, wallet_address, wallet_type, is_wallet_user, created_at FROM users WHERE username_hash = ?",
		usernameHash,
	).Scan(&user.ID, &user.UsernameHash, &user.UsernameEncryptedPwd, &user.UsernameEncryptedSeed, &user.PasswordHash, &user.PasswordEncryptedSeed, &user.SeedEncrypted, &user.PublicKeyEncrypted, &user.PrivateKeyEncrypted, &user.TwoFASecretEncrypted, &user.WalletAddress, &user.WalletType, &user.IsWalletUser, &user.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

func GetDefaultIdentity(userID int) (*Identity, error) {
	var identity Identity
	err := DB.QueryRow(
		"SELECT id, user_id, public_key, private_key_encrypted, alias, is_default, created_at, nft_mint_address, nft_metadata_uri, nft_image_uri, nft_minted_at FROM identities WHERE user_id = ? AND is_default = TRUE",
		userID,
	).Scan(&identity.ID, &identity.UserID, &identity.PublicKey, &identity.PrivateKeyEncrypted, &identity.Alias, &identity.IsDefault, &identity.CreatedAt, &identity.NFTMintAddress, &identity.NFTMetadataURI, &identity.NFTImageURI, &identity.NFTMintedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get default identity: %w", err)
	}
	return &identity, nil
}

func CreateIdentity(userID int, publicKey, privateKeyEncrypted, alias string, isDefault bool, avatarSVG, avatarSVGSmall string) error {
	_, err := DB.Exec(
		"INSERT INTO identities (user_id, public_key, private_key_encrypted, alias, is_default, nft_mint_address, nft_metadata_uri, nft_image_uri, nft_minted_at, avatar_svg, avatar_svg_small) VALUES (?, ?, ?, ?, ?, '', '', '', NULL, ?, ?)",
		userID, publicKey, privateKeyEncrypted, alias, isDefault, avatarSVG, avatarSVGSmall,
	)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}
	return nil
}

func GetIdentities(userID int) ([]Identity, error) {
	rows, err := DB.Query(
		"SELECT id, user_id, public_key, private_key_encrypted, alias, is_default, created_at, nft_mint_address, nft_metadata_uri, nft_image_uri, nft_minted_at FROM identities WHERE user_id = ?",
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query identities: %w", err)
	}
	defer rows.Close()

	var identities []Identity
	for rows.Next() {
		var identity Identity
		err := rows.Scan(&identity.ID, &identity.UserID, &identity.PublicKey, &identity.PrivateKeyEncrypted, &identity.Alias, &identity.IsDefault, &identity.CreatedAt, &identity.NFTMintAddress, &identity.NFTMetadataURI, &identity.NFTImageURI, &identity.NFTMintedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to scan identity: %w", err)
		}
		identities = append(identities, identity)
	}

	return identities, nil
}

func GetUserByWalletAddress(walletAddress string) (*User, error) {
	var user User
	err := DB.QueryRow(
		"SELECT id, username_hash, username_encrypted_pwd, username_encrypted_seed, password_hash, password_encrypted_seed, seed_encrypted, public_key_encrypted, private_key_encrypted, two_fa_secret_encrypted, wallet_address, wallet_type, is_wallet_user, created_at FROM users WHERE wallet_address = ?",
		walletAddress,
	).Scan(&user.ID, &user.UsernameHash, &user.UsernameEncryptedPwd, &user.UsernameEncryptedSeed, &user.PasswordHash, &user.PasswordEncryptedSeed, &user.SeedEncrypted, &user.PublicKeyEncrypted, &user.PrivateKeyEncrypted, &user.TwoFASecretEncrypted, &user.WalletAddress, &user.WalletType, &user.IsWalletUser, &user.CreatedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &user, nil
}

func CreateWalletUser(walletAddress, walletType string) (*User, error) {
	// First check if wallet user already exists
	existingUser, err := GetUserByWalletAddress(walletAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing wallet user: %w", err)
	}
	if existingUser != nil {
		return existingUser, nil
	}

	// Generate unique username with wallet prefix and random suffix
	randSuffix, err := rand.Int(rand.Reader, big.NewInt(999999))
	if err != nil {
		return nil, fmt.Errorf("failed to generate random suffix: %w", err)
	}
	username := fmt.Sprintf("wallet-%s-%06d", walletAddress[:6], randSuffix)
	password := "" // No password for wallet users

	// Create user with empty password
	user, err := CreateUser(username, password, walletAddress, walletType)
	if err != nil {
		return nil, fmt.Errorf("failed to create wallet user: %w", err)
	}

	// Generate default identity for wallet user
	publicKey, privateKey, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity: %w", err)
	}

	alias, err := GenerateUserAlias()
	if err != nil {
		return nil, fmt.Errorf("failed to generate alias: %w", err)
	}

	err = CreateIdentity(user.ID, publicKey, privateKey, alias, true, "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to create identity: %w", err)
	}

	return user, nil
}

type SignupData struct {
	UsernameHash      string            `json:"username_hash"`
	UsernameEncrypted map[string]string `json:"username_encrypted"`
	PasswordHash      string            `json:"password_hash"`
	Alias             string            `json:"alias"`
	PublicKey         string            `json:"public_key"`
}

type SigninData struct {
	UsernameHash string `json:"username_hash"`
	PasswordHash string `json:"password_hash"`
}

type TwoFAData struct {
	Code string `json:"code"`
}

func AuthenticateUser(signinData SigninData, twoFAData *TwoFAData) (*User, error) {
	if signinData.UsernameHash == "" {
		return nil, fmt.Errorf("username required")
	}

	user, err := GetUserByUsernameHash(signinData.UsernameHash)
	if err != nil {
		return nil, fmt.Errorf("authentication error: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Skip password check for wallet users
	if !user.IsWalletUser {
		if signinData.PasswordHash == "" {
			return nil, fmt.Errorf("password required for standard users")
		}
		// Verify password hash matches using bcrypt
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(signinData.PasswordHash)); err != nil {
			return nil, fmt.Errorf("invalid credentials")
		}

		// Verify 2FA if enabled
		if user.TwoFASecretEncrypted != "" {
			if twoFAData == nil || twoFAData.Code == "" {
				return nil, fmt.Errorf("2FA code required")
			}

			// Decrypt 2FA secret
			secret, err := crypto.DecryptWithPassword(user.TwoFASecretEncrypted, signinData.PasswordHash, DefaultCryptoAuditLogger, &user.ID)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt 2FA secret: %w", err)
			}
			defer crypto.ZeroMemory([]byte(secret))

			// Verify TOTP code
			if !crypto.VerifyTOTP(secret, twoFAData.Code) {
				return nil, fmt.Errorf("invalid 2FA code")
			}
		}
	}

	return user, nil
}

func ProcessSignup(signupData SignupData) (*User, error) {
	// Validate required fields
	if signupData.UsernameHash == "" || signupData.PasswordHash == "" ||
		signupData.UsernameEncrypted == nil || signupData.PublicKey == "" {
		return nil, fmt.Errorf("all signup fields are required")
	}

	// Begin database transaction
	tx, err := DB.Begin()
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// Generate seed phrase
	seedPhrase, err := crypto.GenerateSeedPhrase(nil) // Will load words internally
	if err != nil {
		return nil, fmt.Errorf("failed to generate seed phrase: %w", err)
	}

	// Encrypt seed with password
	seedEncrypted, err := crypto.EncryptWithPassword(seedPhrase, signupData.PasswordHash, DefaultCryptoAuditLogger, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt seed: %w", err)
	}

	// Generate deterministic key pair from seed
	publicKey, privateKey, err := crypto.GenerateDeterministicKeyPair(seedPhrase)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Encrypt keys with password
	publicKeyEncrypted, err := crypto.EncryptWithPassword(publicKey, signupData.PasswordHash, DefaultCryptoAuditLogger, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt public key: %w", err)
	}
	privateKeyEncrypted, err := crypto.EncryptWithPassword(privateKey, signupData.PasswordHash, DefaultCryptoAuditLogger, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Generate and encrypt 2FA secret
	twoFASecret, err := crypto.GenerateTwoFASecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate 2FA secret: %w", err)
	}
	twoFASecretEncrypted, err := crypto.EncryptWithPassword(twoFASecret, signupData.PasswordHash, DefaultCryptoAuditLogger, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt 2FA secret: %w", err)
	}

	// Convert map to JSON string for decryption
	usernameEncryptedJSON, err := json.Marshal(signupData.UsernameEncrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encrypted username: %w", err)
	}

	// Decrypt username for storage
	decryptedUsername, err := crypto.DecryptWithKey(string(usernameEncryptedJSON), []byte(signupData.PasswordHash), DefaultCryptoAuditLogger, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt username: %w", err)
	}

	// Create user with all encrypted fields
	result, err := tx.Exec(
		`INSERT INTO users (
			username_hash, 
			username_encrypted_pwd, 
			password_hash,
			seed_encrypted,
			public_key_encrypted,
			private_key_encrypted,
			two_fa_secret_encrypted
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		signupData.UsernameHash,
		decryptedUsername,
		signupData.PasswordHash,
		seedEncrypted,
		publicKeyEncrypted,
		privateKeyEncrypted,
		twoFASecretEncrypted,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err)
	}

	// Create identity within same transaction
	_, err = tx.Exec(
		"INSERT INTO identities (user_id, public_key, private_key_encrypted, alias, is_default) VALUES (?, ?, ?, ?, TRUE)",
		userID, signupData.PublicKey, privateKeyEncrypted, signupData.Alias,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity: %w", err)
	}

	// Commit transaction
	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Clean sensitive data from memory
	crypto.ZeroMemory([]byte(seedPhrase))
	crypto.ZeroMemory([]byte(privateKey))
	crypto.ZeroMemory([]byte(twoFASecret))

	// Get the full user details after commit
	user, err := GetUserByUsernameHash(signupData.UsernameHash)
	if err != nil {
		return nil, fmt.Errorf("failed to verify user creation: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("user not found after creation")
	}

	return user, nil
}
