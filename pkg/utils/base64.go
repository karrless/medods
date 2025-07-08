// Package utils is a collection of utility functions
package utils

import "encoding/base64"

// EncodeBase64 encodes a string to base64
func EncodeBase64(str string) string {
	return base64.URLEncoding.EncodeToString([]byte(str))
}

// DecodeBase64 decodes a string from base64
func DecodeBase64(str string) (string, error) {
	data, err := base64.URLEncoding.DecodeString(str)
	return string(data), err
}
