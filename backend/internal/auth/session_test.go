package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"step-ca-webui/internal/db"
)

func TestSessionLifecycle(t *testing.T) {
	database, err := db.NewDatabase(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}

	admin := db.AdminUser{
		Username:     "sessionadmin",
		PasswordHash: "test-hash",
	}
	if err := database.DB.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}

	token, err := CreateSession(database.DB, admin.ID)
	if err != nil {
		t.Fatal(err)
	}

	if len(token) != 43 {
		t.Fatalf("expected 43-character token, got %d", len(token))
	}

	hash := sha256.Sum256([]byte(token))
	expectedHash := hex.EncodeToString(hash[:])

	var session db.AdminSession
	if err := database.DB.First(&session).Error; err != nil {
		t.Fatal(err)
	}

	if session.TokenHash != expectedHash {
		t.Fatal("database does not contain expected token hash")
	}

	if session.TokenHash == token {
		t.Fatal("raw session token was stored")
	}

	if session.ExpiresAt.Before(time.Now()) {
		t.Fatal("new session is already expired")
	}

	foundAdmin, err := ValidateSession(database.DB, token)
	if err != nil {
		t.Fatal(err)
	}

	if foundAdmin.ID != admin.ID {
		t.Fatal("session resolved to incorrect administrator")
	}

	if err := RevokeSession(database.DB, token); err != nil {
		t.Fatal(err)
	}

	if _, err := ValidateSession(database.DB, token); err == nil {
		t.Fatal("revoked session remained valid")
	}
}

func TestSessionTokensAreUnique(t *testing.T) {
	database, err := db.NewDatabase(filepath.Join(t.TempDir(), "unique.db"))
	if err != nil {
		t.Fatal(err)
	}

	admin := db.AdminUser{
		Username:     "uniqueadmin",
		PasswordHash: "test-hash",
	}
	if err := database.DB.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}

	first, err := CreateSession(database.DB, admin.ID)
	if err != nil {
		t.Fatal(err)
	}

	second, err := CreateSession(database.DB, admin.ID)
	if err != nil {
		t.Fatal(err)
	}

	if first == second {
		t.Fatal("two sessions received identical tokens")
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	database, err := db.NewDatabase(filepath.Join(t.TempDir(), "expired.db"))
	if err != nil {
		t.Fatal(err)
	}

	admin := db.AdminUser{
		Username:     "expiredadmin",
		PasswordHash: "test-hash",
	}
	if err := database.DB.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}

	token, err := CreateSession(database.DB, admin.ID)
	if err != nil {
		t.Fatal(err)
	}

	if err := database.DB.Model(&db.AdminSession{}).
		Where("admin_id = ?", admin.ID).
		Update("expires_at", time.Now().Add(-time.Hour)).Error; err != nil {
		t.Fatal(err)
	}

	if _, err := ValidateSession(database.DB, token); err == nil {
		t.Fatal("expired session was accepted")
	}
}

func TestInvalidSessionRejected(t *testing.T) {
	database, err := db.NewDatabase(filepath.Join(t.TempDir(), "invalid.db"))
	if err != nil {
		t.Fatal(err)
	}

	for _, token := range []string{
		"",
		"invalid",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
		"___________________________________________",
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
	} {
		if _, err := ValidateSession(database.DB, token); err == nil {
			t.Fatalf("invalid token %q was accepted", token)
		}
	}
}
