package db

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Database struct {
	DB *gorm.DB
}

func NewDatabase(dbPath string) (*Database, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Auto-migrate the schema
	if err := db.AutoMigrate(
		&Certificate{},
		&AuditEvent{},
		&CASettings{},
		&AdminUser{},
		&AdminSession{},
	); err != nil {
		return nil, err
	}

	return &Database{DB: db}, nil
}

func (d *Database) GetCASettings() (*CASettings, error) {
	var settings CASettings
	err := d.DB.First(&settings).Error
	if err == gorm.ErrRecordNotFound {
		return &CASettings{}, nil
	}
	return &settings, err
}

func (d *Database) SaveCASettings(settings *CASettings) error {
	if settings.ID == 0 {
		return d.DB.Create(settings).Error
	}
	return d.DB.Save(settings).Error
}

func (d *Database) CreateCertificate(cert *Certificate) error {
	return d.DB.Create(cert).Error
}

func (d *Database) GetCertificate(id string) (*Certificate, error) {
	var cert Certificate
	err := d.DB.Where("id = ?", id).First(&cert).Error
	return &cert, err
}

func (d *Database) ListCertificates(limit, offset int, status string) ([]Certificate, error) {
	var certs []Certificate
	// 2026-10-24: Archived certificates remain stored but are hidden from inventory.
	query := d.DB.Where("archived_at IS NULL").Order("created_at DESC")

	if status != "" {
		query = query.Where("status = ?", status)
	}

	if limit > 0 {
		query = query.Limit(limit)
	}

	if offset > 0 {
		query = query.Offset(offset)
	}

	err := query.Find(&certs).Error
	return certs, err
}

func (d *Database) UpdateCertificate(cert *Certificate) error {
	return d.DB.Save(cert).Error
}

func (d *Database) DeleteCertificate(id string) error {
	return d.DB.Where("id = ?", id).Delete(&Certificate{}).Error
}

func (d *Database) LogAuditEvent(event *AuditEvent) error {
	return d.DB.Create(event).Error
}

func (d *Database) GetAuditEvents(certID string, limit int) ([]AuditEvent, error) {
	var events []AuditEvent
	query := d.DB.Order("timestamp DESC")

	if certID != "" {
		query = query.Where("cert_id = ?", certID)
	}

	if limit > 0 {
		query = query.Limit(limit)
	}

	err := query.Find(&events).Error
	return events, err
}

// 2026-10-24: Archived certificates remain available for historical review.
func (d *Database) ListArchivedCertificates(limit, offset int) ([]Certificate, error) {
	var certs []Certificate
	query := d.DB.Where("archived_at IS NOT NULL").Order("archived_at DESC")

	if limit > 0 {
		query = query.Limit(limit)
	}
	if offset > 0 {
		query = query.Offset(offset)
	}

	err := query.Find(&certs).Error
	return certs, err
}

// 2026-10-24: Archive only revoked or expired certificates.
// The certificate update and audit record share one transaction.
func (d *Database) ArchiveCertificate(id string) error {
	return d.DB.Transaction(func(tx *gorm.DB) error {
		var cert Certificate

		if err := tx.Where("id = ?", id).First(&cert).Error; err != nil {
			return err
		}

		if cert.ArchivedAt != nil {
			return errors.New("certificate is already archived")
		}

		if cert.Status != "revoked" && !cert.NotAfter.Before(time.Now()) {
			return errors.New("only revoked or expired certificates can be archived")
		}

		now := time.Now().UTC()

		result := tx.Model(&Certificate{}).
			Where("id = ? AND archived_at IS NULL", id).
			Update("archived_at", now)

		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return errors.New("certificate archive state changed; retry")
		}

		return tx.Create(&AuditEvent{
			CertID:    id,
			Who:       "system",
			Action:    "archived",
			Details:   fmt.Sprintf("Certificate archived; status=%s; serial=%s", cert.Status, cert.Serial),
			Timestamp: now,
		}).Error
	})
}

// 2026-10-24: Restore inventory visibility without contacting step-ca.
// Restoration never changes certificate validity or revocation status.
func (d *Database) RestoreCertificate(id string) error {
	return d.DB.Transaction(func(tx *gorm.DB) error {
		var cert Certificate

		if err := tx.Where("id = ?", id).First(&cert).Error; err != nil {
			return err
		}

		if cert.ArchivedAt == nil {
			return errors.New("certificate is not archived")
		}

		now := time.Now().UTC()

		result := tx.Model(&Certificate{}).
			Where("id = ? AND archived_at IS NOT NULL", id).
			Update("archived_at", nil)

		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return errors.New("certificate archive state changed; retry")
		}

		return tx.Create(&AuditEvent{
			CertID:    id,
			Who:       "system",
			Action:    "restored",
			Details:   fmt.Sprintf("Certificate restored to inventory; serial=%s", cert.Serial),
			Timestamp: now,
		}).Error
	})
}
