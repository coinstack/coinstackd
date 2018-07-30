// Copyright (c) 2016 BLOCKO INC.
package opencontracts

import (
	"bytes"
	"testing"
)

// TestCompatLegacyAES256CBC tests legacy encryption
// for contract body version 1
func TestCompatLegacyAES256CBC(t *testing.T) {
	testBytes := []byte("test1234")
	testPWBytes := []byte("password")

	cbytes, err := legacyEncryptAES256CBC(testBytes, testPWBytes)
	if err != nil {
		t.Errorf("fail to encrypt: %v", err)
	}

	pbytes, err := legacyDecryptAES256CBC(cbytes, testPWBytes)
	if err != nil {
		t.Errorf("fail to decrypt: %v", err)
	}
	t.Logf("decrypted plain text = %v", string(pbytes))

	if !bytes.Equal(pbytes, testBytes) {
		t.Fatal("something wrong")
	}
}

// TestCompatLegacyAES256CBCNoDigest tests legacy encryption
// for contract body version 2
func TestCompatLegacyAES256CBCNoDigest(t *testing.T) {
	testBytes := []byte("test1234")
	testPWBytes := []byte("password")

	cbytes, err := legacyEncryptAES256CBCNoDigest(testBytes, testPWBytes)
	if err != nil {
		t.Errorf("fail to encrypt: %v", err)
	}

	pbytes, err := legacyDecryptAES256CBCNoDigest(cbytes, testPWBytes)
	if err != nil {
		t.Errorf("fail to decrypt: %v", err)
	}
	t.Logf("decrypted plain text = %v", string(pbytes))

	if !bytes.Equal(pbytes, testBytes) {
		t.Fatal("something wrong")
	}
}
