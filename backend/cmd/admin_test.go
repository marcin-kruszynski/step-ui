package main

import (
	"path/filepath"
	"testing"
	"time"

	"step-ca-webui/internal/auth"
	"step-ca-webui/internal/db"
)

func TestResetAdminPasswordDatabaseTransaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-test.db")

	database, err := db.NewDatabase(path)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}

	sqlDB, err := database.DB.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()

	originalHash, err := auth.HashPassword("OriginalTestPassword123!")
	if err != nil {
		t.Fatal(err)
	}

	admin := db.AdminUser{
		Username:     "testadmin",
		PasswordHash: originalHash,
	}

	if err := database.DB.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}

	session := db.AdminSession{
		AdminID:   admin.ID,
		TokenHash: "test-session-hash",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	if err := database.DB.Create(&session).Error; err != nil {
		t.Fatal(err)
	}

	newHash, err := auth.HashPassword("ReplacementTestPassword456!")
	if err != nil {
		t.Fatal(err)
	}

	// Exercise the actual password-reset implementation.
	err = updateAdminPassword(database.DB, admin.ID, newHash)

	if err != nil {
		t.Fatalf("password reset transaction failed: %v", err)
	}

	var updated db.AdminUser
	if err := database.DB.First(&updated, admin.ID).Error; err != nil {
		t.Fatal(err)
	}

	if !auth.VerifyPassword("ReplacementTestPassword456!", updated.PasswordHash) {
		t.Fatal("new password does not verify")
	}

	if auth.VerifyPassword("OriginalTestPassword123!", updated.PasswordHash) {
		t.Fatal("old password still verifies")
	}

	var sessions int64
	if err := database.DB.Model(&db.AdminSession{}).
		Where("admin_id = ?", admin.ID).
		Count(&sessions).Error; err != nil {
		t.Fatal(err)
	}

	if sessions != 0 {
		t.Fatalf("expected zero sessions after reset, got %d", sessions)
	}

	var events []db.AuditEvent
	if err := database.DB.
		Where("action = ?", "admin.password_reset").
		Find(&events).Error; err != nil {
		t.Fatal(err)
	}

	if len(events) != 1 {
		t.Fatalf("expected one password-reset audit event, got %d", len(events))
	}

	if events[0].Who != admin.Username {
		t.Fatalf("expected audit actor %q, got %q", admin.Username, events[0].Who)
	}

	if events[0].Timestamp.IsZero() {
		t.Fatal("password-reset audit event has no timestamp")
	}

	if events[0].CertID != "" {
		t.Fatal("authentication audit event unexpectedly references a certificate")
	}
}

func TestInsertAdminCreatesAuditEvent(t *testing.T) {
	database, err := db.NewDatabase(filepath.Join(t.TempDir(), "auth-create-test.db"))
	if err != nil {
		t.Fatal(err)
	}

	hash, err := auth.HashPassword("TestPassword123!")
	if err != nil {
		t.Fatal(err)
	}

	if err := insertAdmin(database.DB, "testadmin", hash); err != nil {
		t.Fatalf("administrator creation failed: %v", err)
	}

	var admins []db.AdminUser
	if err := database.DB.Find(&admins).Error; err != nil {
		t.Fatal(err)
	}

	if len(admins) != 1 {
		t.Fatalf("expected one administrator, got %d", len(admins))
	}

	if admins[0].Username != "testadmin" {
		t.Fatalf("unexpected administrator username: %q", admins[0].Username)
	}

	var events []db.AuditEvent
	if err := database.DB.
		Where("action = ?", "admin.create").
		Find(&events).Error; err != nil {
		t.Fatal(err)
	}

	if len(events) != 1 {
		t.Fatalf("expected one creation audit event, got %d", len(events))
	}

	if events[0].Who != "testadmin" {
		t.Fatalf("unexpected audit actor: %q", events[0].Who)
	}

	if events[0].Timestamp.IsZero() {
		t.Fatal("creation audit event has no timestamp")
	}

	if err := insertAdmin(database.DB, "anotheradmin", hash); err == nil {
		t.Fatal("expected duplicate administrator creation to fail")
	}

	var adminCount, eventCount int64

	if err := database.DB.Model(&db.AdminUser{}).Count(&adminCount).Error; err != nil {
		t.Fatal(err)
	}

	if err := database.DB.Model(&db.AuditEvent{}).
		Where("action = ?", "admin.create").
		Count(&eventCount).Error; err != nil {
		t.Fatal(err)
	}

	if adminCount != 1 || eventCount != 1 {
		t.Fatalf(
			"duplicate attempt changed database: admins=%d events=%d",
			adminCount,
			eventCount,
		)
	}
}

func TestInsertAdminRollsBackWhenAuditFails(t *testing.T) {
	database, err := db.NewDatabase(filepath.Join(t.TempDir(), "auth-rollback-test.db"))
	if err != nil {
		t.Fatal(err)
	}

	hash, err := auth.HashPassword("TestPassword123!")
	if err != nil {
		t.Fatal(err)
	}

	// Simulate an audit persistence failure in this disposable database.
	if err := database.DB.Exec("DROP TABLE audit_events").Error; err != nil {
		t.Fatal(err)
	}

	if err := insertAdmin(database.DB, "rollbackadmin", hash); err == nil {
		t.Fatal("expected administrator creation to fail when audit storage fails")
	}

	var count int64
	if err := database.DB.Model(&db.AdminUser{}).Count(&count).Error; err != nil {
		t.Fatal(err)
	}

	if count != 0 {
		t.Fatalf("administrator creation was not rolled back: %d accounts remain", count)
	}
}

func TestResetAdminPasswordRollsBackWhenAuditFails(t *testing.T) {
	database, err := db.NewDatabase(filepath.Join(t.TempDir(), "reset-rollback-test.db"))
	if err != nil {
		t.Fatal(err)
	}

	oldPassword := "OriginalPassword123!"
	newPassword := "ReplacementPassword123!"

	oldHash, err := auth.HashPassword(oldPassword)
	if err != nil {
		t.Fatal(err)
	}

	newHash, err := auth.HashPassword(newPassword)
	if err != nil {
		t.Fatal(err)
	}

	admin := db.AdminUser{
		Username:     "rollbackadmin",
		PasswordHash: oldHash,
	}
	if err := database.DB.Create(&admin).Error; err != nil {
		t.Fatal(err)
	}

	session := db.AdminSession{
		AdminID:   admin.ID,
		TokenHash: "rollback-test-session",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := database.DB.Create(&session).Error; err != nil {
		t.Fatal(err)
	}

	// Force the audit write to fail in this disposable database.
	if err := database.DB.Exec("DROP TABLE audit_events").Error; err != nil {
		t.Fatal(err)
	}

	if err := updateAdminPassword(database.DB, admin.ID, newHash); err == nil {
		t.Fatal("expected password reset to fail when audit storage fails")
	}

	var stored db.AdminUser
	if err := database.DB.First(&stored, admin.ID).Error; err != nil {
		t.Fatal(err)
	}

	if !auth.VerifyPassword(oldPassword, stored.PasswordHash) {
		t.Fatal("original password was not preserved after rollback")
	}

	if auth.VerifyPassword(newPassword, stored.PasswordHash) {
		t.Fatal("replacement password was committed despite audit failure")
	}

	var sessionCount int64
	if err := database.DB.Model(&db.AdminSession{}).
		Where("admin_id = ?", admin.ID).
		Count(&sessionCount).Error; err != nil {
		t.Fatal(err)
	}

	if sessionCount != 1 {
		t.Fatalf("expected original session to survive rollback, got %d", sessionCount)
	}
}
