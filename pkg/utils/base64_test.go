package utils

import (
	"testing"
)

func TestEncodeBase64(t *testing.T) {
	str := "Hello, World!"
	expected := "SGVsbG8sIFdvcmxkIQ=="
	encodedStr := EncodeBase64(str)

	if encodedStr != expected {
		t.Errorf("Expected %s, got %s", expected, encodedStr)
	}
}

func TestDecodeBase64(t *testing.T) {
	str := "SGVsbG8sIFdvcmxkIQ=="
	expected := "Hello, World!"
	decodedStr, err := DecodeBase64(str)

	if err != nil {
		t.Fatal("Error decoding base64:", err)
	}

	if decodedStr != expected {
		t.Errorf("Expected %s, got %s", expected, decodedStr)
	}

	str = "invalid_base64_data!!"

	_, err = DecodeBase64(str)

	if err == nil {
		t.Errorf("DecodeBase64 should have failed with invalid input, but no error was returned")
	}
}
