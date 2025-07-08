package utils

import "testing"

func TestHashString(t *testing.T) {
	password := "securePassword123"

	hashedPassword, err := HashString(password)
	if err != nil {
		t.Fatal("Error hashing password:", err)
	}

	if hashedPassword == "" {
		t.Fatal("Hashed password is empty")
	}

	success, err := CheckStirngHash(password, hashedPassword)
	if !success {
		t.Error("Password check failed", err)
	}

	wrongPassword := "wrongPassword123"
	success, err = CheckStirngHash(wrongPassword, hashedPassword)
	if success {
		t.Error("Password check succeeded for wrong password", err)
	}

	hashedPassword2, err := HashString(password)
	if hashedPassword == hashedPassword2 {
		t.Error("Hashed password is the same")
	}

}
