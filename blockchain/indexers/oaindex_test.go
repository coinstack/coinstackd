// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"bytes"
	"testing"

	"github.com/coinstack/coinstackd/blockchain/indexers/openassets"
	_ "github.com/coinstack/coinstackd/database/ffldb"
)

// func TestOAIndex(t *testing.T) {
// 	// create test context
// 	dbPath := filepath.Join(os.TempDir(), "test-oandex")
// 	_ = os.RemoveAll(dbPath)
// 	idb, err := database.Create(dbType, dbPath, blockDataNet)
// 	if err != nil {
// 		t.Errorf("Failed to create test database (%s) %v", dbType, err)
// 		return
// 	}
// 	defer os.RemoveAll(dbPath)
// 	defer idb.Close()

// 	// create indexer and test
// 	permIndexer := NewOAIndex(nil)

// 	idb.Update(func(tx database.Tx) error {
// 		permIndexer.Create(tx)
// 		return nil
// 	})
// 	// save oa metadata
// 	idb.saveMeta(dbTx database.Tx, txHash *wire.ShaHash, outputMeta []*openassets.Meta)
// 	// fetch oa metadata
// 	outputMeta := idb.fetchMeta(dbTx database.Tx, txHash *wire.ShaHash)

// 	if nil == outputMeta {
// 		t.Error("failed to fetch meta")
// 	}
// }

// OutputType   MetaType // 2 bytes
// 	MajorVersion uint16               // 2 bytes
// 	MinorVersion uint16               // 2 bytes
// 	Quantity     uint64               // 8 bytes
// 	AssetID      []byte               // 20 bytes
// 	Script       []byte

func TestOAMetaSerialize(t *testing.T) {
	before := []*openassets.Meta{
		{
			OutputType:   openassets.MetaIssuance,
			MajorVersion: 0,
			MinorVersion: 3,
			Quantity:     314,
			AssetID:      []byte("teststring1aaaaaaaaa"),
		},
		{
			OutputType:   openassets.MetaTransfer,
			MajorVersion: 0,
			MinorVersion: 3,
			Quantity:     315,
			AssetID:      []byte("teststring2aaaaaaaaa"),
		},
		{
			OutputType:   openassets.MetaUncolored,
			MajorVersion: 0,
			MinorVersion: 3,
			Quantity:     0,
			AssetID:      []byte("teststring3aaaaaaaaa"),
		},
	}

	beforeSerialized := serializeOAIndexEntry(before)

	if nil == beforeSerialized {
		t.Error("serialized failed")
	}

	t.Log(len(beforeSerialized))

	var after []*openassets.Meta
	deserializeOAIndexEntry(beforeSerialized, &after)

	if len(after) != 3 {
		t.Error("deserialize failed")
	}

	for i := 0; i < 3; i++ {
		if after[i].OutputType != before[i].OutputType {
			t.Error("before after mismatch")
		}
		if after[i].Quantity != before[i].Quantity {
			t.Error("before after mismatch")
		}
		if !bytes.Equal(after[i].AssetID, before[i].AssetID) {
			t.Error("before after mismatch")
		}
	}
}
