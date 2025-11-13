package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"text/template"
	"time"

	"deskrow/admin_commands"
	"deskrow/admin_ws_tunnel"
	"deskrow/crypto"
	"deskrow/db"
	"deskrow/logs"
	"deskrow/metrics"
	"deskrow/middleware"
	"deskrow/rate"
	"deskrow/shared/logging"

	svg "github.com/ajstarks/svgo"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/joho/godotenv"
)

var (
	// Global metrics service instance
	metricsService *metrics.MetricsService
	// Global logging service instance
	loggingService *logs.LogService
)

type server struct {
	limiter *rate.Limiter
}

func (s *server) handleLanding(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/templates/landing.html")
}

func (s *server) handleApp(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/templates/app.html")
}

func (s *server) handleAuth(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/auth", http.StatusMovedPermanently)
}

func (s *server) handleAuthPage(w http.ResponseWriter, r *http.Request) {
	// Generate session ID and timestamp
	sessionID := generateSessionID()
	timestamp := time.Now().Unix()

	// Create template data with server data
	data := struct {
		SessionID string
		Timestamp int64
	}{
		SessionID: sessionID,
		Timestamp: timestamp,
	}

	// Parse and execute template
	tmpl, err := template.ParseFiles("../frontend/templates/auth.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func generateSessionID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

func (s *server) handleTransactionView(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Transaction view"))
}

func (s *server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success": false, "detail": "Invalid request data"}`))
		return
	}

	// Decrypt request data using session key
	sessionID := r.Header.Get("X-Session-ID")
	timestampStr := r.Header.Get("X-Timestamp")
	if sessionID == "" || timestampStr == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success": false, "detail": "Missing session headers"}`))
		return
	}

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success": false, "detail": "Invalid timestamp"}`))
		return
	}

	// Derive decryption key from session ID and timestamp
	decryptionKey, err := crypto.DeriveDecryptionKey(sessionID, timestamp)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success": false, "detail": "Failed to derive decryption key"}`))
		return
	}

	// Decrypt the request body with nil logger and userID since we don't have them yet
	decryptedBody, err := crypto.DecryptWithKey(string(body), decryptionKey, nil, nil)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success": false, "detail": "Failed to decrypt request"}`))
		return
	}

	// Parse the decrypted request
	var request struct {
		UsernameHash      string `json:"username_hash"`
		EncryptedPassword struct {
			IV   string `json:"iv"`
			Data string `json:"data"`
		} `json:"encrypted_password"`
		EphemeralPublicKey map[string]interface{} `json:"ephemeral_public_key"`
	}

	if err := json.Unmarshal([]byte(decryptedBody), &request); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success": false, "detail": "Invalid request format"}`))
		return
	}

	if s.limiter != nil {
		if blocked, _ := s.limiter.IsBlocked(request.UsernameHash); blocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"success": false, "detail": "Too many attempts"}`))
			return
		}
	}

	// Convert encrypted password to bytes
	iv, err := hex.DecodeString(request.EncryptedPassword.IV)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success": false, "detail": "Invalid IV format"}`))
		return
	}

	ciphertext, err := hex.DecodeString(request.EncryptedPassword.Data)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success": false, "detail": "Invalid ciphertext format"}`))
		return
	}

	// Import server's private key
	privateKey, err := crypto.ImportPrivateKey(os.Getenv("SERVER_PRIVATE_KEY"))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success": false, "detail": "Server configuration error"}`))
		return
	}

	// Derive shared secret
	sharedSecret, err := crypto.DeriveSharedSecret(privateKey, request.EphemeralPublicKey)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success": false, "detail": "Failed to derive shared secret"}`))
		return
	}

	// Decrypt password
	passwordBytes, err := crypto.DecryptAESGCM(sharedSecret, iv, ciphertext)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success": false, "detail": "Failed to decrypt password"}`))
		return
	}
	password := string(passwordBytes)

	// Create signin data with decrypted password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success": false, "detail": "Failed to hash password"}`))
		return
	}

	signinData := db.SigninData{
		UsernameHash: request.UsernameHash,
		PasswordHash: string(passwordHash),
	}

	authUser, authErr := db.AuthenticateUser(signinData, nil)
	if authErr != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success": false, "detail": "Internal server error"}`))
		return
	}
	if authUser == nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"success": false, "detail": "Invalid alias or password"}`))
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": authUser.ID,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})

	secret, err := crypto.GetSessionSecret(crypto.CurrentSessionSecretVersion())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success": false, "detail": "Failed to get signing secret"}`))
		return
	}
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success": false, "detail": "Failed to generate token"}`))
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    tokenString,
		Path:     "/",
		HttpOnly: true,
		Secure:   os.Getenv("ENV") == "production",
		SameSite: http.SameSiteLaxMode,
	})
	if r.Header.Get("X-Requested-With") == "XMLHttpRequest" {
		identity, err := db.GetDefaultIdentity(authUser.ID)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"success": false, "detail": "Failed to get user identity"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":   true,
			"redirect":  "/app",
			"userAlias": identity.Alias,
		})
	} else {
		http.Redirect(w, r, "/app", http.StatusFound)
	}
}

func (s *server) handleSignUp(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		UsernameHash          string `json:"username_hash"`
		UsernameEncryptedPwd  string `json:"username_encrypted_pwd"`
		UsernameEncryptedSeed string `json:"username_encrypted_seed"`
		PasswordHash          string `json:"password_hash"`
		PasswordEncryptedSeed string `json:"password_encrypted_seed"`
		Alias                 string `json:"alias"`
		PublicKey             string `json:"public_key"`
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success": false, "detail": "Error reading request"}`))
		return
	}

	log.Printf("Received signup request: %s", string(bodyBytes))

	err = json.Unmarshal(bodyBytes, &requestBody)
	if err != nil {
		log.Printf("Error decoding request body: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success": false, "detail": "Invalid request data"}`))
		return
	}

	user := &db.User{
		UsernameHash:          requestBody.UsernameHash,
		UsernameEncryptedPwd:  requestBody.UsernameEncryptedPwd,
		UsernameEncryptedSeed: requestBody.UsernameEncryptedSeed,
		PasswordHash:          requestBody.PasswordHash,
		PasswordEncryptedSeed: requestBody.PasswordEncryptedSeed,
	}

	result, err := db.DB.Exec(
		"INSERT INTO users (username_hash, username_encrypted_pwd, username_encrypted_seed, password_hash, password_encrypted_seed) VALUES (?, ?, ?, ?, ?)",
		user.UsernameHash, user.UsernameEncryptedPwd, user.UsernameEncryptedSeed, user.PasswordHash, user.PasswordEncryptedSeed,
	)
	if err != nil {
		log.Printf("Failed to create user: %v", err)
		w.Header().Set("Content-Type", "application/json")

		response := map[string]interface{}{
			"success": false,
			"detail":  "Failed to create account",
		}

		if err.Error() == "UNIQUE constraint failed: users.username_hash" {
			w.WriteHeader(http.StatusBadRequest)
			response["detail"] = "Username already taken"
			response["fieldErrors"] = map[string]string{
				"username": "Username already taken",
			}
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			response["detail"] = "Failed to create account - please try again"
		}

		json.NewEncoder(w).Encode(response)
		return
	}

	userID, err := result.LastInsertId()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success": false, "detail": "Failed to get user ID"}`))
		return
	}

	_, err = db.DB.Exec(
		"INSERT INTO identities (user_id, public_key, private_key_encrypted, alias, is_default) VALUES (?, ?, ?, ?, TRUE)",
		userID, requestBody.PublicKey, "", requestBody.Alias,
	)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success": false, "detail": "Failed to create identity"}`))
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})

	secret, err := crypto.GetSessionSecret(crypto.CurrentSessionSecretVersion())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success": false, "detail": "Failed to get signing secret"}`))
		return
	}
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success": false, "detail": "Failed to generate session"}`))
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    tokenString,
		Path:     "/",
		HttpOnly: true,
		Secure:   os.Getenv("ENV") == "production",
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"redirect": "/app",
	})
}

func (s *server) handleCreateTransaction(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Create transaction"))
}

func (s *server) handleGenerateIdentity(w http.ResponseWriter, r *http.Request) {
	publicKey, _, err := db.GenerateKeyPair()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success": false, "detail": "Failed to generate key pair"}`))
		return
	}

	userAlias, err := db.GenerateUserAlias()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success": false, "detail": "Failed to generate user alias"}`))
		return
	}

	avatarSVG := generateIdenticonSVG(publicKey, 80)

	// Store the identity temporarily (we'll implement this fully later)
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		sessionID = fmt.Sprintf("%x", time.Now().UnixNano())
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"userKey":   publicKey,
		"userAlias": userAlias,
		"avatarSVG": avatarSVG,
		"sessionID": sessionID,
	})
}

func generateIdenticonSVG(hash string, size int) string {
	var buf bytes.Buffer
	canvas := svg.New(&buf)

	canvas.Start(size, size)
	canvas.Rect(0, 0, size, size, "fill:#f0f0")

	for i := 0; i < 5; i++ {
		x := i * size / 5
		for j := 0; j < 5; j++ {
			y := j * size / 5
			if (int(hash[i+j]) % 2) == 0 {
				canvas.Rect(x, y, size/5, size/5, "fill:#333333")
			}
		}
	}

	canvas.End()
	return buf.String()
}

func (s *server) handleGetTransaction(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Get transaction"))
}

func (s *server) handleSignOut(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *server) handleWalletAuth(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		WalletAddress string `json:"walletAddress"`
		WalletType    string `json:"walletType"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success": false, "detail": "Invalid request data"}`))
		return
	}

	user, err := db.GetUserByWalletAddress(requestBody.WalletAddress)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success": false, "detail": "Error checking wallet user"}`))
		return
	}

	if user == nil {
		user, err = db.CreateWalletUser(requestBody.WalletAddress, requestBody.WalletType)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"success": false, "detail": "Failed to create wallet user"}`))
			return
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("SESSION_SECRET")))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success": false, "detail": "Failed to generate token"}`))
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    tokenString,
		Path:     "/",
		HttpOnly: true,
		Secure:   os.Getenv("ENV") == "production",
		SameSite: http.SameSiteLaxMode,
	})

	identity, err := db.GetDefaultIdentity(user.ID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success": false, "detail": "Failed to get user identity"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"redirect":  "/app",
		"userAlias": identity.Alias,
	})
}

func (s *server) handleCheckUsername(w http.ResponseWriter, r *http.Request) {
	var requestBody struct {
		UsernameHash string `json:"username_hash"`
	}

	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"success": false, "detail": "Invalid request data"}`))
		return
	}

	exists, err := db.UsernameExists(requestBody.UsernameHash)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"success": false, "detail": "Error checking username"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if exists {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true, "available": false}`))
	} else {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success": true, "available": true}`))
	}
}

func main() {
	// Load .env file from .env
	if err := godotenv.Load(".env"); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Removed redundant admin HTTP server goroutine.
	// Admin UI/API is handled by the separate backend/admin/main.go application.

	parseEnvDuration := func(key string, fallback time.Duration) time.Duration {
		if val := os.Getenv(key); val != "" {
			d, err := time.ParseDuration(val)
			if err == nil {
				return d
			}
		}
		return fallback
	}

	noRateLimit := flag.Bool("no-rate-limit", false, "Disable rate limiting completely")
	maxAttempts := flag.Int("max-attempts", func() int {
		if val := os.Getenv("RATE_LIMIT_MAX_ATTEMPTS"); val != "" {
			if i, err := strconv.Atoi(val); err == nil {
				return i
			}
		}
		return 5
	}(), "Maximum attempts before blocking")
	windowSize := flag.Duration("window-size",
		parseEnvDuration("RATE_LIMIT_WINDOW_SIZE", 5*time.Minute),
		"Time window for counting attempts")
	ipBanDuration := flag.Duration("ip-ban-duration",
		parseEnvDuration("RATE_LIMIT_IP_BAN_DURATION", 30*time.Minute),
		"Duration for IP bans")
	userBanDuration := flag.Duration("user-ban-duration",
		parseEnvDuration("RATE_LIMIT_USER_BAN_DURATION", 1*time.Hour),
		"Duration for user bans")
	flag.Parse()

	// Validate required environment variables
	requiredVars := []string{"SESSION_SECRET", "CSRF_SECRET", "ENCRYPTION_ROOT_SEED"}
	for _, v := range requiredVars {
		if os.Getenv(v) == "" {
			log.Fatalf("Required environment variable %s is not set", v)
		}
	}

	// Create data directory if it doesn't exist
	if err := os.MkdirAll("data", 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// Initialize Databases
	if err := db.Init(loggingService); err != nil { // Initializes main DB (data/deskrow.db) and backup DB (data/deskrow_bak.db)
		log.Fatalf("Failed to initialize main database: %v", err)
	}
	defer db.DB.Close()      // Ensure main DB is closed on exit
	defer db.CloseBackupDB() // Ensure backup DB is closed on exit

	if err := db.InitSecretsDB(); err != nil { // Initialize secrets DB (data/secrets.db)
		log.Fatalf("Failed to initialize secrets database: %v", err)
	}
	defer db.CloseSecretsDB() // Ensure secrets DB is closed on exit

	// Create KeyStorage implementation using SecretsDatabase
	secretsDB := db.GetSecretsDB() // Get singleton instance
	keyStore := db.NewSecretsDBKeyStorage(secretsDB)

	// Initialize crypto package stores with the new KeyStorage implementation
	if err := crypto.InitKeyStore(keyStore); err != nil {
		log.Fatalf("Failed to initialize key store: %v", err)
	}
	if err := crypto.InitSessionSecretStore(keyStore); err != nil {
		log.Fatalf("Failed to initialize session secret store: %v", err)
	}
	if err := crypto.InitCSRFSecretStore(keyStore); err != nil {
		log.Fatalf("Failed to initialize CSRF secret store: %v", err)
	}

	// Initialize and start the admin WebSocket tunnel server for metrics/logs feed (port 3001)
	adminWSTunnelServer := admin_ws_tunnel.NewAdminWSTunnelServer(
		nil, // We'll pass the adminWSTunnelServer itself as the sender, so no need for logs channel here
		nil, // We'll pass the adminWSTunnelServer itself as the sender, so no need for metrics channel here
	)
	if err := adminWSTunnelServer.InitializeECDHKeys(); err != nil {
		log.Fatalf("Failed to initialize admin WebSocket tunnel ECDH keys: %v", err)
	}
	
	// Start admin WebSocket tunnel server on port 3001
	go func() {
		adminWSTunnelAddr := ":3001"
		log.Printf("Starting admin WebSocket tunnel server on %s", adminWSTunnelAddr)
		httpServer := &http.Server{
			Addr:    adminWSTunnelAddr,
			Handler: adminWSTunnelServer,
		}
		if err := httpServer.ListenAndServe(); err != nil {
			log.Printf("Admin WebSocket tunnel server error: %v", err)
		}
	}()

	// Initialize logging service with admin WebSocket tunnel logs sender
	var err error
	loggingService, err = logs.NewLogService("data", adminWSTunnelServer)
	if err != nil {
		log.Fatalf("Failed to create logging service: %v", err)
	}
	log.Println("Logging service initialized with admin WebSocket tunnel integration")

	// Initialize metrics database
	metricsDB, err := metrics.NewMetricsDatabase("data/metrics")
	if err != nil {
		log.Fatalf("Failed to initialize metrics database: %v", err)
	}
	defer metricsDB.Close()

	// Initialize metrics service with admin WebSocket tunnel metrics sender and metrics database
	metricsService = metrics.NewMetricsService(adminWSTunnelServer, metricsDB)
	defer metricsService.Stop()
	log.Println("Metrics service initialized with admin WebSocket tunnel and database integration")

	// Initialize admin commands handler for admin commands (port 3002)
	adminCommandHandler := admin_commands.NewCommandHandler()
	
	// Start admin commands server on port 3002
	go func() {
		adminCommandAddr := ":3002"
		log.Printf("Starting admin commands server on %s", adminCommandAddr)
		httpServer := &http.Server{
			Addr:    adminCommandAddr,
			Handler: adminCommandHandler,
		}
		if err := httpServer.ListenAndServe(); err != nil {
			log.Printf("Admin commands server error: %v", err)
		}
	}()

	log.Println("Admin WebSocket tunnel server (port 3001) and admin commands server (port 3002) started")

	// --- Configure Standard Logger Output ---
	// Create logging service writer with info level
	logWriter := logs.NewLogWriter(loggingService, logging.LevelInfo)
	// Create a multi-writer to write to both stderr and the logging service
	multiWriter := io.MultiWriter(os.Stderr, logWriter)
	// Set the standard logger's output
	log.SetOutput(multiWriter)
	// Optional: Set log flags (e.g., include file/line number)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Println("Standard logger configured to write to stderr and logging service.")
	// --- End Logger Configuration ---

	r := chi.NewRouter()

	// Setup CORS middleware
	corsMiddleware := cors.New(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:3000",
			"http://localhost:3001",
			"http://localhost:8080",
			"http://localhost:8000",
			"https://*.vercel.app", // Allow Vercel deployments
			"https://*.deskrow.com", // Allow production domain
		},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-Requested-With", "X-Session-ID", "X-Timestamp"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value for Chrome
	})
	r.Use(corsMiddleware.Handler)

	// Apply Logging Middleware
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			log.Printf("%s %s %v", r.Method, r.URL.Path, time.Since(start))
		})
	})

	srv := &server{}
	if !*noRateLimit {
		srv.limiter = rate.NewLimiter(rate.Config{
			MaxAttempts:         *maxAttempts,
			WindowSize:          *windowSize,
			IPBanDuration:       *ipBanDuration,
			UsernameBanDuration: *userBanDuration,
		})
	}

	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("../frontend/static"))))

	r.Route("/api/v1", func(r chi.Router) {
		// Public endpoint
		r.Get("/server-time", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"serverTime": time.Now().Unix(),
				"timezone":   time.Now().Format("MST"),
			})
		})

		r.Group(func(r chi.Router) {
			if srv.limiter != nil {
				r.Use(middleware.RateLimit(srv.limiter))
			}
			r.Post("/auth/signin", srv.handleSignIn)
			r.Post("/auth/signup", srv.handleSignUp)
			r.Post("/auth/signout", srv.handleSignOut)
			r.Post("/auth/check-username", srv.handleCheckUsername)
			r.Post("/auth/wallet", srv.handleWalletAuth)
		})
		r.Post("/identity/generate", srv.handleGenerateIdentity)
		// TODO: Add authentication middleware for user-specific transaction endpoints
		r.Post("/transactions", srv.handleCreateTransaction)
		r.Get("/transactions/{hash}", srv.handleGetTransaction)

		// --- Admin Routes Removed from main router ---
		// Admin commands are now handled by the dedicated server started by startAdminCommandServer
	})

	// SPA fallback - serve index.html for all non-API routes to let frontend router handle them
	// This would be used if frontend is also deployed with the backend
	// r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
	//     // Only if frontend files are served by backend
	//     http.ServeFile(w, r, "../frontend/templates/index.html")
	// })

	// Use Render's $PORT environment variable if available, otherwise SERVER_PORT, otherwise default to 3000
	port := os.Getenv("PORT") // Render provides this
	if port == "" {
		port = os.Getenv("SERVER_PORT") // fallback to original config
	}
	if port == "" {
		port = "3000" // default
	}

	fmt.Printf("Server running on port %s\n", port)

	// Enable HTTPS if cert files exist
	certFile := os.Getenv("SSL_CERT_FILE")
	keyFile := os.Getenv("SSL_KEY_FILE")
	if certFile != "" && keyFile != "" {
		log.Printf("Starting HTTPS server on port %s", port)
		log.Fatal(http.ListenAndServeTLS(":"+port, certFile, keyFile, r))
	} else {
		log.Printf("Starting HTTP server on port %s (no SSL certs found)", port)
		log.Fatal(http.ListenAndServe(":"+port, r))
	}
}
