package glance

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestAuthTokenGenerationAndVerification(t *testing.T) {
	secret, err := makeAuthSecretKey(AUTH_SECRET_KEY_LENGTH)
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	secretBytes, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		t.Fatalf("Failed to decode secret key: %v", err)
	}

	if len(secretBytes) != AUTH_SECRET_KEY_LENGTH {
		t.Fatalf("Secret key length is not %d bytes", AUTH_SECRET_KEY_LENGTH)
	}

	now := time.Now()
	username := "admin"

	token, err := generateSessionToken(username, secretBytes, now)
	if err != nil {
		t.Fatalf("Failed to generate session token: %v", err)
	}

	usernameHashBytes, shouldRegen, err := verifySessionToken(token, secretBytes, now)
	if err != nil {
		t.Fatalf("Failed to verify session token: %v", err)
	}

	if shouldRegen {
		t.Fatal("Token should not need to be regenerated immediately after generation")
	}

	computedUsernameHash, err := computeUsernameHash(username, secretBytes)
	if err != nil {
		t.Fatalf("Failed to compute username hash: %v", err)
	}

	if !bytes.Equal(usernameHashBytes, computedUsernameHash) {
		t.Fatal("Username hash does not match the expected value")
	}

	// Test token regeneration
	timeRightAfterRegenPeriod := now.Add(AUTH_TOKEN_VALID_PERIOD - AUTH_TOKEN_REGEN_BEFORE + 2*time.Second)
	_, shouldRegen, err = verifySessionToken(token, secretBytes, timeRightAfterRegenPeriod)
	if err != nil {
		t.Fatalf("Token verification should not fail during regeneration period, err: %v", err)
	}

	if !shouldRegen {
		t.Fatal("Token should have been marked for regeneration")
	}

	// Test token expiration
	_, _, err = verifySessionToken(token, secretBytes, now.Add(AUTH_TOKEN_VALID_PERIOD+2*time.Second))
	if err == nil {
		t.Fatal("Expected token verification to fail after token expiration")
	}

	// Test tampered token
	decodedToken, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("Failed to decode token: %v", err)
	}

	// If any of the bytes are off by 1, the token should be considered invalid
	for i := range len(decodedToken) {
		tampered := make([]byte, len(decodedToken))
		copy(tampered, decodedToken)
		tampered[i] += 1

		_, _, err = verifySessionToken(base64.StdEncoding.EncodeToString(tampered), secretBytes, now)
		if err == nil {
			t.Fatalf("Expected token verification to fail for tampered token at index %d", i)
		}
	}
}

func newTestAuthApplication(t *testing.T, allowBasicAuth bool) *application {
	t.Helper()

	secret, err := makeAuthSecretKey(AUTH_SECRET_KEY_LENGTH)
	if err != nil {
		t.Fatalf("Failed to generate secret key: %v", err)
	}

	secretBytes, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		t.Fatalf("Failed to decode secret key: %v", err)
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	app := &application{
		RequiresAuth:           true,
		authSecretKey:          secretBytes,
		usernameHashToUsername: make(map[string]string),
		failedAuthAttempts:     make(map[string]*failedAuthAttempt),
	}
	app.Config.Auth.AllowBasicAuth = allowBasicAuth
	app.Config.Auth.Users = map[string]*user{
		"admin": {PasswordHash: passwordHash},
	}

	usernameHash, err := computeUsernameHash("admin", secretBytes)
	if err != nil {
		t.Fatalf("Failed to compute username hash: %v", err)
	}
	app.usernameHashToUsername[string(usernameHash)] = "admin"

	return app
}

func TestBasicAuth(t *testing.T) {
	t.Run("valid credentials are authorized and receive a session cookie", func(t *testing.T) {
		app := newTestAuthApplication(t, true)

		r := httptest.NewRequest("GET", "/", nil)
		r.SetBasicAuth("admin", "password123")
		w := httptest.NewRecorder()

		if !app.isAuthorized(w, r) {
			t.Fatal("Request with valid basic auth credentials should be authorized")
		}

		cookies := w.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Name != AUTH_SESSION_COOKIE_NAME || cookies[0].Value == "" {
			t.Fatalf("Expected a session cookie to be set, got %v", cookies)
		}
	})

	t.Run("invalid credentials are not authorized", func(t *testing.T) {
		app := newTestAuthApplication(t, true)

		r := httptest.NewRequest("GET", "/", nil)
		r.SetBasicAuth("admin", "wrongpassword")

		if app.isAuthorized(httptest.NewRecorder(), r) {
			t.Fatal("Request with invalid basic auth credentials should not be authorized")
		}
	})

	t.Run("credentials are ignored when basic auth is disabled", func(t *testing.T) {
		app := newTestAuthApplication(t, false)

		r := httptest.NewRequest("GET", "/", nil)
		r.SetBasicAuth("admin", "password123")

		if app.isAuthorized(httptest.NewRecorder(), r) {
			t.Fatal("Basic auth credentials should be ignored when allow-basic-auth is not enabled")
		}
	})

	t.Run("unauthorized requests are challenged when basic auth is enabled", func(t *testing.T) {
		app := newTestAuthApplication(t, true)

		w := httptest.NewRecorder()
		app.handleUnauthorizedResponse(w, httptest.NewRequest("GET", "/", nil), redirectToLogin)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}

		if !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Basic ") {
			t.Fatalf("Expected a basic auth challenge, got %q", w.Header().Get("WWW-Authenticate"))
		}
	})

	t.Run("unauthorized requests are redirected when basic auth is disabled", func(t *testing.T) {
		app := newTestAuthApplication(t, false)

		w := httptest.NewRecorder()
		app.handleUnauthorizedResponse(w, httptest.NewRequest("GET", "/", nil), redirectToLogin)

		if w.Code != http.StatusSeeOther {
			t.Fatalf("Expected status %d, got %d", http.StatusSeeOther, w.Code)
		}

		if w.Header().Get("WWW-Authenticate") != "" {
			t.Fatal("No basic auth challenge should be sent when allow-basic-auth is not enabled")
		}
	})
}
