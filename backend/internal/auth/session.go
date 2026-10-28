package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"gorm.io/gorm"

	"step-ca-webui/internal/db"
)

const SessionDuration = 12 * time.Hour

var ErrInvalidSession = errors.New("invalid or expired session")

func validSessionToken(token string) bool {
	if len(token) != 43 {
		return false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != 32 {
		return false
	}

	return base64.RawURLEncoding.EncodeToString(decoded) == token
}

func sessionTokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// CreateSession generates an opaque token and stores only its SHA-256 hash.
// The raw token must be delivered to the client through a secure cookie.
func CreateSession(database *gorm.DB, adminID uint) (string, error) {
	tokenBytes := make([]byte, 32)

	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}

	token := base64.RawURLEncoding.EncodeToString(tokenBytes)

	session := db.AdminSession{
		AdminID:   adminID,
		TokenHash: sessionTokenHash(token),
		ExpiresAt: time.Now().UTC().Add(SessionDuration),
	}

	if err := database.Create(&session).Error; err != nil {
		return "", err
	}

	return token, nil
}

// ValidateSession verifies that a token exists, has not expired,
// and belongs to an existing administrator.
func ValidateSession(database *gorm.DB, token string) (*db.AdminUser, error) {
	if !validSessionToken(token) {
		return nil, ErrInvalidSession
	}

	var session db.AdminSession

	if err := database.
		Where("token_hash = ? AND expires_at > ?",
			sessionTokenHash(token), time.Now().UTC()).
		First(&session).Error; err != nil {
		return nil, ErrInvalidSession
	}

	var admin db.AdminUser

	if err := database.First(&admin, session.AdminID).Error; err != nil {
		return nil, ErrInvalidSession
	}

	return &admin, nil
}

// RevokeSession deletes the stored token hash, invalidating the session.
func RevokeSession(database *gorm.DB, token string) error {
	if !validSessionToken(token) {
		return ErrInvalidSession
	}

	return database.
		Where("token_hash = ?", sessionTokenHash(token)).
		Delete(&db.AdminSession{}).Error
}
