// Copyright (c) 2016 BLOCKO INC.
// Package client comes from github.com/coinstack/coinstack-client
// And this error_test.go file comes from error_test.go of coinstack-client
package client

import (
	"encoding/json"
	"testing"
)

func TestError(t *testing.T) {
	err := NewCoinStackError(AccessDenied).SetCause("Invalid credentials.")
	bytes, _ := json.Marshal(err)
	jsonString := string(bytes)
	if len(jsonString) <= 0 {
		t.Error("failed to marshal")
	}
}
