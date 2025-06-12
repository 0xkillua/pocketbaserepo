package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v66/github" // <<< THIS LINE IS FIXED
	"github.com/joho/godotenv"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// Config holds all application configuration.
type Config struct {
	AppID                    string
	PrivateKeyPath           string
	InstallationID           string
	Repo                     string // Repository name to clone
	Owner                    string // Owner of the repository
	CloneBasePath            string // Base directory for cloning repos
	PocketbaseURL            string
	PocketbaseAuthCollection string
	PocketbaseAdminEmail     string
	PocketbaseAdminPass      string
}

var logger *zap.Logger

func init() {
	var err error
	logger, err = zap.NewDevelopment()
	if err != nil {
		panic(fmt.Sprintf("❌ Failed to initialize logger: %v", err))
	}
}

// loadConfig reads environment variables from a .env file or the OS.
func loadConfig() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		logger.Warn("No .env file found, reading from environment variables")
	}

	cfg := &Config{
		AppID:                    os.Getenv("APP_ID"),
		PrivateKeyPath:           os.Getenv("PRIVATE_KEY_PATH"),
		InstallationID:           os.Getenv("INSTALLATION_ID"),
		Owner:                    os.Getenv("OWNER"),
		Repo:                     os.Getenv("REPO"),
		CloneBasePath:            os.Getenv("CLONE_BASE_PATH"),
		PocketbaseURL:            os.Getenv("POCKETBASE_URL"),
		PocketbaseAuthCollection: os.Getenv("POCKETBASE_AUTH_COLLECTION"),
		PocketbaseAdminEmail:     os.Getenv("POCKETBASE_ADMIN_EMAIL"),
		PocketbaseAdminPass:      os.Getenv("POCKETBASE_ADMIN_PASSWORD"),
	}

	// Validate that essential configuration is not empty.
	required := []string{
		cfg.AppID, cfg.PrivateKeyPath, cfg.InstallationID, cfg.Owner, cfg.Repo,
		cfg.PocketbaseURL, cfg.PocketbaseAuthCollection, cfg.PocketbaseAdminEmail, cfg.PocketbaseAdminPass,
	}
	for _, field := range required {
		if field == "" {
			return nil, fmt.Errorf("one or more required environment variables are missing")
		}
	}

	return cfg, nil
}

// --- PocketBase Client ---

type PocketBaseClient struct {
	Client  *http.Client
	BaseURL string
	Token   string
}

// NewPocketBaseClient creates and authenticates a new client for interacting with PocketBase.
func NewPocketBaseClient(cfg *Config) (*PocketBaseClient, error) {
	httpClient := &http.Client{Timeout: 10 * time.Second}

	healthURL := fmt.Sprintf("%s/api/health", cfg.PocketbaseURL)
	resp, err := httpClient.Get(healthURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PocketBase at %s: %w", cfg.PocketbaseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pocketBase health check failed with status: %d", resp.StatusCode)
	}
	logger.Info("✅ Connected to PocketBase successfully.")

	pbClient := &PocketBaseClient{
		Client:  httpClient,
		BaseURL: cfg.PocketbaseURL,
	}

	authData := map[string]string{
		"identity": cfg.PocketbaseAdminEmail,
		"password": cfg.PocketbaseAdminPass,
	}
	body, err := json.Marshal(authData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal auth data: %w", err)
	}

	authURL := fmt.Sprintf("%s/api/collections/%s/auth-with-password", pbClient.BaseURL, cfg.PocketbaseAuthCollection)
	logger.Info("Attempting authentication", zap.String("url", authURL))

	req, err := http.NewRequest("POST", authURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	authResp, err := pbClient.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with PocketBase: %w", err)
	}
	defer authResp.Body.Close()

	if authResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(authResp.Body)
		return nil, fmt.Errorf("pocketBase auth failed with status %d: %s", authResp.StatusCode, string(respBody))
	}

	var authResponsePayload struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(authResp.Body).Decode(&authResponsePayload); err != nil {
		return nil, fmt.Errorf("failed to decode PocketBase auth response: %w", err)
	}
	pbClient.Token = authResponsePayload.Token
	logger.Info("✅ Authenticated with PocketBase successfully.")

	if err := pbClient.verifyOrCreateRepoCollection(); err != nil {
		return nil, fmt.Errorf("failed to verify or create 'repo' collection: %w", err)
	}

	return pbClient, nil
}

// verifyOrCreateRepoCollection ensures the 'repo' collection exists in PocketBase.
func (pb *PocketBaseClient) verifyOrCreateRepoCollection() error {
	collectionURL := fmt.Sprintf("%s/api/collections/repo", pb.BaseURL)
	req, err := http.NewRequest("GET", collectionURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", pb.Token)

	resp, err := pb.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		logger.Info("✅ PocketBase 'repo' collection already exists.")
		return nil
	}

	if resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("failed to check for collection, status: %d", resp.StatusCode)
	}

	// Collection does not exist, so create it.
	logger.Info("'repo' collection not found, creating it...")
	schema := []map[string]interface{}{
		{"system": false, "name": "repo_id", "type": "number", "required": true, "options": map[string]interface{}{"min": 1}},
		{"system": false, "name": "is_private", "type": "bool", "required": true},
		{"system": false, "name": "owner", "type": "text", "required": true},
		{"system": false, "name": "name", "type": "text", "required": true},
		{"system": false, "name": "clone_path", "type": "text", "required": true},
	}

	payload := map[string]interface{}{
		"name":       "repo",
		"type":       "base",
		"listRule":   "@request.auth.id != \"\"", // Requires auth
		"viewRule":   "@request.auth.id != \"\"", // Requires auth
		"createRule": "@request.auth.id != \"\"", // Requires auth
		"schema":     schema,
	}

	body, _ := json.Marshal(payload)
	createURL := fmt.Sprintf("%s/api/collections", pb.BaseURL)
	createReq, err := http.NewRequest("POST", createURL, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", pb.Token)

	createResp, err := pb.Client.Do(createReq)
	if err != nil {
		return err
	}
	defer createResp.Body.Close()

	if createResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(createResp.Body)
		return fmt.Errorf("failed to create collection: status %d, response: %s", createResp.StatusCode, string(respBody))
	}

	logger.Info("✅ Successfully created 'repo' collection in PocketBase.")
	return nil
}

// StoreRepoMetadata stores repository metadata in the PocketBase 'repo' collection.
func (pb *PocketBaseClient) StoreRepoMetadata(data map[string]interface{}) error {
	body, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal repo data: %w", err)
	}

	recordsURL := fmt.Sprintf("%s/api/collections/repo/records", pb.BaseURL)
	req, err := http.NewRequest("POST", recordsURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create store request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", pb.Token)

	resp, err := pb.Client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute store request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to store repo metadata, status %d: %s", resp.StatusCode, string(respBody))
	}

	logger.Info("✅ Successfully stored repository metadata in PocketBase", zap.Any("data", data))
	return nil
}

// --- GitHub Client ---

// generateJWT creates a JWT token for GitHub App authentication.
func generateJWT(cfg *Config) (string, error) {
	privateKey, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return "", fmt.Errorf("could not read private key from %s: %w", cfg.PrivateKeyPath, err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return "", fmt.Errorf("could not parse private key: %w", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(), // Max expiration is 10 minutes
		"iss": cfg.AppID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return token.SignedString(key)
}

// NewGitHubClient creates a GitHub client authenticated as an app installation.
func NewGitHubClient(ctx context.Context, cfg *Config) (*github.Client, string, error) {
	jwtToken, err := generateJWT(cfg)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate JWT: %w", err)
	}
	logger.Info("✅ Generated GitHub App JWT.")

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: jwtToken})
	appClient := github.NewClient(oauth2.NewClient(ctx, ts))

	installationID, err := strconv.ParseInt(cfg.InstallationID, 10, 64)
	if err != nil {
		return nil, "", fmt.Errorf("invalid INSTALLATION_ID: %w", err)
	}

	tokenOpts := &github.InstallationTokenOptions{}
	installationToken, resp, err := appClient.Apps.CreateInstallationToken(ctx, installationID, tokenOpts)
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(resp.Body)
			return nil, "", fmt.Errorf("failed to create installation token (status: %d): %s - %w", resp.StatusCode, string(body), err)
		}
		return nil, "", fmt.Errorf("failed to create installation token: %w", err)
	}
	logger.Info("✅ Generated GitHub installation token.")

	installationTokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: installationToken.GetToken()})
	httpClient := oauth2.NewClient(ctx, installationTokenSource)
	ghClient := github.NewClient(httpClient)

	return ghClient, installationToken.GetToken(), nil
}

// --- Main Application Logic ---

func processRepository(ctx context.Context, cfg *Config, ghClient *github.Client, ghToken string, pbClient *PocketBaseClient) error {
	logger.Info("Fetching repository details...", zap.String("owner", cfg.Owner), zap.String("repo", cfg.Repo))

	repo, _, err := ghClient.Repositories.Get(ctx, cfg.Owner, cfg.Repo)
	if err != nil {
		return fmt.Errorf("failed to fetch repository '%s/%s': %w", cfg.Owner, cfg.Repo, err)
	}
	logger.Info("✅ Found repository", zap.String("full_name", repo.GetFullName()))

	clonePath := filepath.Join(cfg.CloneBasePath, repo.GetFullName())

	repoData := map[string]interface{}{
		"repo_id":    repo.GetID(),
		"is_private": repo.GetPrivate(),
		"owner":      repo.Owner.GetLogin(),
		"name":       repo.GetName(),
		"clone_path": clonePath,
	}
	if err := pbClient.StoreRepoMetadata(repoData); err != nil {
		return fmt.Errorf("failed to store repo metadata: %w", err)
	}

	cloneURL := fmt.Sprintf("https://x-access-token:%s@github.com/%s.git", ghToken, repo.GetFullName())

	if err := os.MkdirAll(clonePath, 0755); err != nil {
		return fmt.Errorf("failed to create clone directory '%s': %w", clonePath, err)
	}

	dir, _ := os.ReadDir(clonePath)
	if len(dir) > 0 {
		logger.Warn("Clone directory is not empty. Git clone might fail.", zap.String("path", clonePath))
	}

	logger.Info("Cloning repository...", zap.String("from", repo.GetFullName()), zap.String("to", clonePath))
	cmd := exec.Command("git", "clone", cloneURL, clonePath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone command failed: %w", err)
	}

	logger.Info("✅ Successfully cloned repository.", zap.String("repo", repo.GetFullName()))
	return nil
}

func startHealthCheckServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "GitHub App service is healthy and running!")
	})
	server := &http.Server{
		Addr:         ":3000",
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("🚀 Health check server listening on http://127.0.0.1:3000")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server failed to start", zap.Error(err))
		}
	}()
	return server
}

func main() {
	defer logger.Sync()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := loadConfig()
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	pbClient, err := NewPocketBaseClient(cfg)
	if err != nil {
		logger.Fatal("Failed to initialize PocketBase client", zap.Error(err))
	}

	ghClient, ghToken, err := NewGitHubClient(ctx, cfg)
	if err != nil {
		logger.Fatal("Failed to initialize GitHub client", zap.Error(err))
	}

	server := startHealthCheckServer()

	if err := processRepository(ctx, cfg, ghClient, ghToken, pbClient); err != nil {
		logger.Fatal("Failed to process repository", zap.Error(err))
	}

	<-ctx.Done()
	logger.Info("Shutdown signal received, starting graceful shutdown...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Fatal("Server shutdown failed", zap.Error(err))
	}
	logger.Info("✅ Server shut down gracefully.")
}
