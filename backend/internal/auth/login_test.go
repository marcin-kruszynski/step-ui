package auth

import (
	"errors"
	"path/filepath"
	"testing"

	"step-ca-webui/internal/db"
)

func setupLoginTest(t *testing.T) (*db.Database, db.AdminUser) {
	t.Helper()

	database, err := db.NewDatabase(filepath.Join(t.TempDir(), "login-test.db"))
	if err != nil {
		t.Fatal(err)
	}

	sqlDB, err := database.DB.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqlDB.Close() })

	hash, err := HashPassword("CorrectPassword123!")
	if err != nil {
		t.Fatal(err)
	}

	admin := db.AdminUser{
		Username:     "testadmin",
		PasswordHash: hash,
	}

	if err := database.DB.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}

	return database, admin
}

func TestLoginSuccess(t *testing.T) {
	database, admin := setupLoginTest(t)

	token, err := Login(database.DB, "testadmin", "CorrectPassword123!")
	if err != nil {
		t.Fatal(err)
	}

	authenticated, err := ValidateSession(database.DB, token)
	if err != nil {
		t.Fatal(err)
	}
	if authenticated.ID != admin.ID {
		t.Fatal("session belongs to wrong administrator")
	}

	var sessions int64
	if err := database.DB.Model(&db.AdminSession{}).
		Count(&sessions).Error; err != nil {
		t.Fatal(err)
	}
	if sessions != 1 {
		t.Fatalf("expected one session, got %d", sessions)
	}

	var audits int64
	if err := database.DB.Model(&db.AuditEvent{}).
		Where("action = ? AND who = ?", "admin.login", admin.Username).
		Count(&audits).Error; err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("expected one login audit event, got %d", audits)
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	database, _ := setupLoginTest(t)

	cases := []struct {
		username string
		password string
	}{
		{"testadmin", "WrongPassword123!"},
		{"missingadmin", "CorrectPassword123!"},
	}

	for _, tc := range cases {
		token, err := Login(database.DB, tc.username, tc.password)
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("expected invalid credentials for %q, got %v", tc.username, err)
		}
		if token != "" {
			t.Fatal("failed login returned a session token")
		}
	}

	var sessions int64
	if err := database.DB.Model(&db.AdminSession{}).
		Count(&sessions).Error; err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("failed logins created %d sessions", sessions)
	}

	var audits int64
	if err := database.DB.Model(&db.AuditEvent{}).
		Where("action = ?", "admin.login").
		Count(&audits).Error; err != nil {
		t.Fatal(err)
	}
	if audits != 0 {
		t.Fatalf("failed logins created %d success audit events", audits)
	}
}

func TestLoginAuditRollback(t *testing.T) {
	database, _ := setupLoginTest(t)

	if err := database.DB.Exec("DROP TABLE audit_events").Error; err != nil {
		t.Fatal(err)
	}

	token, err := Login(database.DB, "testadmin", "CorrectPassword123!")
	if err == nil {
		t.Fatal("login succeeded despite audit persistence failure")
	}
	if token != "" {
		t.Fatal("failed transaction returned a session token")
	}

	var sessions int64
	if err := database.DB.Model(&db.AdminSession{}).
		Count(&sessions).Error; err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("audit failure left %d sessions committed", sessions)
	}
}
