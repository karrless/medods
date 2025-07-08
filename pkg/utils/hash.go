// Package utils is a collection of utility functions
package utils

import "golang.org/x/crypto/bcrypt"

// HashString returns the bcrypt hash of the password
func HashString(str string) (string, error) {
	hashedStr, err := bcrypt.GenerateFromPassword([]byte(str), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedStr), nil
}

// CheckStirngHash checks if the password is correct
func CheckStirngHash(str, hash string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(str))
	return err == nil, err
}
