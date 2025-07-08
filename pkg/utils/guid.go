// Package utils is a collection of utility functions
package utils

import "github.com/google/uuid"

// GenerateGUID generates a GUID
func GenerateGUID() string {
	return uuid.NewString()
}

// IsGUID checks if the string is a GUID
func IsGUID(guid string) bool {
	_, err := uuid.Parse(guid)
	return err == nil
}
