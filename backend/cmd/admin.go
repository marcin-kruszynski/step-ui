package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
	"gorm.io/gorm"

	"step-ca-webui/internal/auth"
	"step-ca-webui/internal/config"
	"step-ca-webui/internal/db"
)

func runAdminCLI(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: main admin <create|reset-password>")
	}

	switch args[0] {
	case "create", "reset-password":
	default:
		return errors.New("usage: main admin <create|reset-password>")
	}

	cfg := config.Load()

	database, err := db.NewDatabase(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}

	sqlDB, err := database.DB.DB()
	if err != nil {
		return err
	}
	defer sqlDB.Close()

	switch args[0] {
	case "create":
		return createAdmin(database.DB)
	case "reset-password":
		return resetAdminPassword(database.DB)
	}

	return nil
}

func createAdmin(database *gorm.DB) error {
	var count int64

	if err := database.Model(&db.AdminUser{}).Count(&count).Error; err != nil {
		return err
	}

	if count != 0 {
		return errors.New("an administrator already exists; use admin reset-password")
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Administrator username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	username = strings.TrimSpace(username)

	if username == "" || len(username) > 64 {
		return errors.New("username must contain between 1 and 64 characters")
	}

	password, err := promptPassword()
	if err != nil {
		return err
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}

	err = insertAdmin(database, username, hash)

	if err != nil {
		return err
	}

	fmt.Printf("Administrator %q created successfully.\n", username)
	return nil
}

func insertAdmin(database *gorm.DB, username, hash string) error {
	return database.Transaction(func(tx *gorm.DB) error {
		var existing int64

		if err := tx.Model(&db.AdminUser{}).Count(&existing).Error; err != nil {
			return err
		}

		if existing != 0 {
			return errors.New("administrator already exists")
		}

		if err := tx.Create(&db.AdminUser{
			Username:     username,
			PasswordHash: hash,
		}).Error; err != nil {
			return err
		}

		return tx.Create(&db.AuditEvent{
			Who:       username,
			Action:    "admin.create",
			Details:   "Administrator account created through local CLI",
			Timestamp: time.Now(),
		}).Error
	})
}

func resetAdminPassword(database *gorm.DB) error {
	var admins []db.AdminUser

	if err := database.Limit(2).Find(&admins).Error; err != nil {
		return err
	}

	if len(admins) != 1 {
		return errors.New("password recovery requires exactly one administrator")
	}

	admin := admins[0]

	fmt.Printf("Resetting password for administrator: %s\n", admin.Username)

	password, err := promptPassword()
	if err != nil {
		return err
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}

	if err := updateAdminPassword(database, admin.ID, hash); err != nil {
		return err
	}

	fmt.Println("Password reset successfully. Existing sessions invalidated.")
	return nil
}

// updateAdminPassword changes the password and invalidates all existing
// sessions atomically. Both the CLI and regression tests use this function.
func updateAdminPassword(database *gorm.DB, adminID uint, hash string) error {
	return database.Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&db.AdminUser{}).
			Where("id = ?", adminID).
			Update("password_hash", hash)

		if result.Error != nil {
			return result.Error
		}

		if result.RowsAffected != 1 {
			return errors.New("administrator no longer exists")
		}

		if err := tx.Where("admin_id = ?", adminID).
			Delete(&db.AdminSession{}).Error; err != nil {
			return err
		}

		var admin db.AdminUser
		if err := tx.First(&admin, adminID).Error; err != nil {
			return err
		}

		return tx.Create(&db.AuditEvent{
			Who:       admin.Username,
			Action:    "admin.password_reset",
			Details:   "Administrator password reset; existing sessions invalidated",
			Timestamp: time.Now(),
		}).Error
	})
}

func promptPassword() (string, error) {
	fd := int(os.Stdin.Fd())

	if !term.IsTerminal(fd) {
		return "", errors.New("password entry requires an interactive terminal")
	}

	fmt.Print("New password: ")
	first, err := term.ReadPassword(fd)
	fmt.Println()

	if err != nil {
		return "", err
	}

	fmt.Print("Confirm password: ")
	second, err := term.ReadPassword(fd)
	fmt.Println()

	if err != nil {
		return "", err
	}

	if string(first) != string(second) {
		return "", errors.New("passwords do not match")
	}

	if len(first) < 12 {
		return "", errors.New("password must contain at least 12 characters")
	}

	return string(first), nil
}
