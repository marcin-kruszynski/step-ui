package db

import "time"

// AdminUser represents a local Step UI administrator.
// PasswordHash stores an encoded Argon2id hash, never a plaintext password.
type AdminUser struct {
	ID           uint   `gorm:"primaryKey"`
	Username     string `gorm:"uniqueIndex;not null"`
	PasswordHash string `gorm:"not null"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// AdminSession represents a revocable authenticated browser session.
// TokenHash contains a SHA-256 digest of a cryptographically random token.
type AdminSession struct {
	ID        uint      `gorm:"primaryKey"`
	AdminID   uint      `gorm:"index;not null"`
	TokenHash string    `gorm:"uniqueIndex;not null"`
	ExpiresAt time.Time `gorm:"index;not null"`
	CreatedAt time.Time
}
