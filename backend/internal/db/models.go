package db

import (
	"time"
)

type Certificate struct {
	ID          string    `gorm:"primaryKey" json:"id"`
	CN          string    `gorm:"index" json:"cn"`
	Serial      string    `json:"serial"` // decimal serial number of the current certificate
	SANs        string    `json:"sans"` // JSON array
	NotAfter    time.Time `gorm:"index" json:"not_after"`
	Status      string    `json:"status"` // active, revoked, expired
	KeyStrategy string    `json:"key_strategy"` // server, csr
	StorageRef  string    `json:"storage_ref"` // ephemeral, or file path
	OwnerUser   string    `json:"owner_user"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type AuditEvent struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	CertID    string    `gorm:"index" json:"cert_id"`
	Who       string    `json:"who"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
	Timestamp time.Time `json:"timestamp"`
}

type CASettings struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	CAURL        string `json:"ca_url"`
	RootFingerprint string `json:"root_fingerprint"`
	ACMEDirectories []string `gorm:"type:text" json:"acme_directories"` // JSON array
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
