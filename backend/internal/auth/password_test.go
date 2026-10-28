package auth

import (
	"strings"
	"testing"
)

func TestHashAndVerifyPassword(t *testing.T) {
	password := "CorrectHorseBatteryStaple2026!"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("unexpected hash format")
	}

	if !VerifyPassword(password, hash) {
		t.Fatal("correct password was rejected")
	}

	if VerifyPassword("WrongPassword123!", hash) {
		t.Fatal("incorrect password was accepted")
	}
}

func TestUniqueSalts(t *testing.T) {
	password := "CorrectHorseBatteryStaple2026!"

	first, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	second, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	if first == second {
		t.Fatal("identical hashes generated for separate salts")
	}
}

func TestShortPassword(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password was accepted")
	}
}

func TestMalformedHashes(t *testing.T) {
	invalid := []string{
		"",
		"plaintext",
		"$argon2id$invalid",
		"$argon2id$v=19$m=999999999,t=3,p=2$bad$bad",
		"$argon2id$v=19$m=65536,t=3,p=2$bad$bad",
	}

	for _, hash := range invalid {
		if VerifyPassword("TestPassword123!", hash) {
			t.Fatalf("malformed hash was accepted: %q", hash)
		}
	}
}
