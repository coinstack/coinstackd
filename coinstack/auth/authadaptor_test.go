// Copyright (c) 2016 BLOCKO INC.
// Package auth comes from github.com/coinstack/coinstack-auth
// And this authadaptor_test.go file comes from authadaptor_test.go of coinstack-auth
package auth

import (
	"testing"
)

func xxxTestGetId(t *testing.T) {
	db, _ := OpenDB("localhost", "auth")
	// db.provisionDB()

	found, _, secretKey, err := db.CheckSecretKey("eb90dbf0-e98c-11e4-b571-0800200c9a66")

	if nil != err {
		t.Error("failed to fetch secretkey")
		t.Log(err)
	}

	if !found {
		t.Error("api key not found")
	}

	if secretKey != "f8bd5b50-e98c-11e4-b571-0800200c9a66" {
		t.Error("failed to fetch secretkey")
	}

	found, _, err = db.CheckToken("f8bd5b50-e98c-11e4-b571-0800200c9a66")
	if nil != err {
		t.Error("failed to check token")
	}
	if found {
		t.Error("token should not be found")
	}

	found, _, err = db.CheckToken("testkey")
	if nil != err {
		t.Error("failed to check token")
	}
	if !found {
		t.Error("token not found")
	}

	db.CloseDB()
}
