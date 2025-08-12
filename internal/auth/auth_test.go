package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_ValidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	apiKey, err := GetAPIKey(headers)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if apiKey != "my-secret-key" {
		t.Errorf("Expected 'my-secret-key', got '%s'", apiKey)
	}
}

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)

	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("Expected ErrNoAuthHeaderIncluded, got %v", err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	testCases := []struct {
		name   string
		header string
	}{
		{"Only ApiKey", "ApiKey"},
		{"Wrong prefix", "Bearer my-key"},
		{"Empty string", ""},
		{"Just key", "my-key"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set("Authorization", tc.header)

			_, err := GetAPIKey(headers)

			if err == nil {
				t.Error("Expected an error, got nil")
			}
		})
	}
}
