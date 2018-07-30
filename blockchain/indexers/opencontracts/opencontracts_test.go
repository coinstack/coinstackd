// Copyright (c) 2016 BLOCKO INC.
package opencontracts

import (
	"bytes"
	"testing"

	"github.com/coinstack/coinstackd/coinstack/crypto"
	"github.com/btcsuite/fastsha256"
	"github.com/vincent-petithory/dataurl"
)

func TestOpenContracts(t *testing.T) {
	// create opencontracts output

	testMarker := []byte{
		0x4f, 0x43, // magic
		0x01, 0x00, // version
		0x00, 0x01, // op issuance
	}

	// prepare test payload
	payload := []byte("{\"type\":\"LSC\",\"body\":\"dGVzdA==\"}")

	hasher := fastsha256.New()
	hasher.Write(payload)
	hashed := hasher.Sum(nil)

	t.Log(hashed)

	encodedPayload := []byte(dataurl.EncodeBytes(payload))

	testMarker = append(testMarker[:], hashed[:]...)
	testMarker = append(testMarker[:], encodedPayload[:]...)

	// try parsing
	marker, ok := parseMarkerPayload(testMarker)
	if !ok {
		t.Fatal("failed to parse marker")
	}

	if marker.OpCode != Issuance {
		t.Error("faile dto parse opcode")
	}

	// test if payload matches
	parsedPayload := marker.PayloadData
	t.Log(string(parsedPayload))

	hasher = fastsha256.New()
	hasher.Write(parsedPayload)
	parsedHashed := hasher.Sum(nil)

	if bytes.Compare(parsedHashed, marker.PayloadHash) != 0 {
		t.Error("sha mismatch")
	}

	if bytes.Compare(parsedHashed, hashed) != 0 {
		t.Error("sha mismatch")
	}

	t.Log(marker.PayloadBody.Type)
	t.Log(string(marker.PayloadBody.Body))
}

// func TestUrl(t *testing.T) {
// 	testUrl, err := url.Parse(`data:text/plain;charset=utf-8;base64,aGV5YQ==`)
// 	t.Log(testUrl.Scheme)

// 	url, err := dataurl.DecodeString(`data:text/plain;charset=utf-8;base64,aGV5YQ==`)
// 	t.Log(url.MediaType.ContentType())

// 	url, err = dataurl.DecodeString("http://google.com")
// 	if nil != err {
// 		t.Fatal(err)
// 	}
// }

func TestCipher(t *testing.T) {
	testBytes := []byte("test1234")
	testPWBytes := []byte("password")

	cbytes, err := crypto.Encrypt(testBytes, testPWBytes)
	if err != nil {
		t.Errorf("fail to encrypt: %v", err)
	}

	pbytes, err := crypto.Decrypt(cbytes, testPWBytes)
	if err != nil {
		t.Errorf("fail to decrypt: %v", err)
	}
	t.Logf("decrypted plain text = %v", string(pbytes))

	if !bytes.Equal(pbytes, testBytes) {
		t.Fatal("something wrong")
	}
}
