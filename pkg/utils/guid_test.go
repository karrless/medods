package utils

import (
	"testing"
)

func TestGenerateGUID(t *testing.T) {
	guid := GenerateGUID()

	if guid == "" {
		t.Error("GUID is empty")
	}

	t.Log(guid)

	guid1 := GenerateGUID()

	if guid1 == guid {
		t.Error("GUIDs are the same")
	}
}
