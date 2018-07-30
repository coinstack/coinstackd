// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"testing"

	"github.com/coinstack/coinstackd/database"
	_ "github.com/coinstack/coinstackd/database/ffldb"
	"github.com/coinstack/coinstackd/wire"
	"github.com/btcsuite/fastsha256"
	"os"
	"path/filepath"
	"runtime/debug"
)

const (
	dbTypeUtxoIndex       = "ffldb"
	blockDataNetUtxoIndex = wire.MainNet
)

func TestUtxoIndex(t *testing.T) {
	// create test context
	dbPath := filepath.Join(os.TempDir(), "test-utxoindex")
	_ = os.RemoveAll(dbPath)
	idb, err := database.Create(dbType, dbPath, blockDataNet)
	if err != nil {
		t.Errorf("Failed to create test database (%s) %v", dbType, err)
		return
	}
	defer os.RemoveAll(dbPath)
	defer idb.Close()

	// create indexer and test
	utxoIndexer := NewUtxoIndex(nil)

	idb.Update(func(tx database.Tx) error {
		utxoIndexer.Create(tx)
		return nil
	})

	idb.Update(func(tx database.Tx) error {
		// test with blocks first
		// simple case
		t.Log("simple test")
		utxoIndexer.addOutput(tx, calcHash("tx1"), 0, 1, "addr1", 0, false, []byte("test"))
		utxoIndexer.addOutput(tx, calcHash("tx2"), 0, 2, "addr1", 0, false, []byte("test"))
		utxoIndexer.addOutput(tx, calcHash("tx3"), 0, 3, "addr1", 0, false, []byte("test"))

		return nil
	})

	checkOutput(t, idb, utxoIndexer, "addr1", 6)

	idb.Update(func(tx database.Tx) error {
		utxoIndexer.addOutput(tx, calcHash("tx4"), 0, 5, "addr2", 1, false, []byte("test"))
		return nil
	})

	checkOutput(t, idb, utxoIndexer, "addr1", 6)

	// use up outputs
	idb.Update(func(tx database.Tx) error {
		utxoIndexer.markOutput(tx, createKey(calcHash("tx3"), 0), "addr1")
		return nil
	})

	checkOutput(t, idb, utxoIndexer, "addr1", 3)
	checkOutput(t, idb, utxoIndexer, "addr2", 5)

	idb.Update(func(tx database.Tx) error {
		utxoIndexer.markOutput(tx, createKey(calcHash("tx2"), 0), "addr1")
		return nil
	})
	checkOutput(t, idb, utxoIndexer, "addr1", 1)

	idb.Update(func(tx database.Tx) error {
		utxoIndexer.markOutput(tx, createKey(calcHash("tx4"), 0), "addr2")
		return nil
	})
	checkOutput(t, idb, utxoIndexer, "addr2", 0)

	// block reorgniazations
	idb.Update(func(tx database.Tx) error {
		utxoIndexer.addOutput(tx, calcHash("tx3"), 0, 3, "addr1", 2, false, []byte("test")) // add output back into utxo set
		return nil
	})
	checkOutput(t, idb, utxoIndexer, "addr1", 4)
}

func checkOutput(t *testing.T, idb database.DB, utxoIndexer *UtxoIndex, addr string, amount int64) {
	sum := int64(0)
	idb.View(func(tx database.Tx) error {
		_, outputs, _ := utxoIndexer.FetchOutputs(tx, addr)
		for _, output := range outputs {
			sum += output.Amount
		}
		return nil
	})

	if sum != amount {
		debug.PrintStack()
		t.Error("utxo output mismatch")
	}
}

func calcHash(payload string) *wire.ShaHash {
	buf := []byte(payload)
	hasher := fastsha256.New()
	hasher.Write(buf)
	hashed, _ := wire.NewShaHash(hasher.Sum(nil))
	return hashed
}

func TestUtxoIndexSerialization(t *testing.T) {
	o1 := Output{
		TxHash:   calcHash("tx1"),
		Vout:     0,
		Amount:   314,
		Height:   10,
		Coinbase: true,
		Script:   []byte("test"),
	}

	serialized := serializeUtxoIndexEntry(&o1)

	o2 := Output{}

	err := deserializeUtxoIndexEntry(serialized, &o2)
	if nil != err {
		t.Error("failed to deserialize")
	}

	if !o2.TxHash.IsEqual(o1.TxHash) || o2.Vout != o1.Vout || o2.Amount != o1.Amount || o2.Height != o1.Height || o2.Coinbase != o1.Coinbase || string(o2.Script) != string(o1.Script) {
		t.Error("serialization mismatch")
	}

	t.Logf("%v:%v - %v at %v (%v) [%v]", o2.TxHash.String(), o2.Vout, o2.Amount, o2.Height, o2.Coinbase, string(o2.Script))

	key := serializeKey(&wire.OutPoint{Hash: *calcHash("test"), Index: 314})

	t.Logf("%v", key)
}
