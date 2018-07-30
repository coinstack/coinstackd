// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coinstack/coinstackd/database"
	_ "github.com/coinstack/coinstackd/database/ffldb"
	"github.com/coinstack/coinstackd/wire"
)

const (
	ismDbType       = "ffldb"
	ismBlockDataNet = wire.MainNet
)

func TestISMIndex(t *testing.T) {
	// create test context
	dbPath := filepath.Join(os.TempDir(), "test-ismindex")
	_ = os.RemoveAll(dbPath)
	idb, err := database.Create(ismDbType, dbPath, ismBlockDataNet)
	if err != nil {
		t.Errorf("Failed to create test database (%s) %v", dbType, err)
		return
	}
	defer os.RemoveAll(dbPath)
	defer idb.Close()

	t.Log("testing ISM index")

	// create indexer and test
	ismIndexer := NewISMIndex(nil, nil, false)

	idb.Update(func(tx database.Tx) error {
		ismIndexer.Create(tx)
		return nil
	})
}
