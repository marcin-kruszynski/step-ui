package auth

import (
	"errors"
	"time"

	"gorm.io/gorm"

	"step-ca-webui/internal/db"
)

var ErrInvalidCredentials = errors.New("invalid username or password")

var dummyPasswordHash = func() string {
	hash, err := HashPassword("not-a-real-administrator-password")
	if err != nil {
		panic("failed to initialize authentication dummy hash")
	}
	return hash
}()

// Login verifies credentials and creates an audited session.
// Both session creation and its audit event are committed atomically.
func Login(database *gorm.DB, username, password string) (string, error) {
	var admin db.AdminUser

	err := database.
		Where("username = ?", username).
		First(&admin).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		// Perform an equivalent Argon2id verification for unknown users.
		// This reduces username-enumeration timing differences.
		VerifyPassword(password, dummyPasswordHash)
		return "", ErrInvalidCredentials
	}

	if err != nil {
		return "", err
	}

	if !VerifyPassword(password, admin.PasswordHash) {
		return "", ErrInvalidCredentials
	}

	var token string

	err = database.Transaction(func(tx *gorm.DB) error {
		var err error

		token, err = CreateSession(tx, admin.ID)
		if err != nil {
			return err
		}

		return tx.Create(&db.AuditEvent{
			Who:       admin.Username,
			Action:    "admin.login",
			Details:   "Administrator authenticated successfully",
			Timestamp: time.Now().UTC(),
		}).Error
	})

	if err != nil {
		return "", err
	}

	return token, nil
}
