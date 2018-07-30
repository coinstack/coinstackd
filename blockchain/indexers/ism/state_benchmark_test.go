// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ism

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/coinstack/coinstackd/database"
	_ "github.com/coinstack/coinstackd/database/ffldb"
	"github.com/coinstack/coinstackd/wire"
)

const (
	benchIsmDbType       = "ffldb"
	benchIsmBlockDataNet = wire.MainNet
)

func StateOperations(numContracts int, numItems int, blockID string, tx database.Tx, ismState *State) error {
	ismState.NewStage(tx, []byte("blockID"))
	// write new instances and database

	// 10 new smart contracts
	for i := 0; i < numContracts; i++ {
		instanceID := []byte(fmt.Sprintf("%v_%v", blockID, i))
		ismState.CreateInstance(tx, instanceID)
		// 100 new data points
		for j := 0; j < numItems; j++ {
			ismState.SetInstanceItem(tx, instanceID, []byte(fmt.Sprintf("hellotestvasd123key_%v", j)), []byte(fmt.Sprintf("helloworldvaluehellovalue_%v", j)))
		}
	}

	return nil
}

func benchmarkISMState(numContracts int, numItems int, b *testing.B) {
	// create test context
	dbPath := filepath.Join(os.TempDir(), "test-ismindex")
	b.Logf("writing db to %v", dbPath)
	_ = os.RemoveAll(dbPath)
	idb, err := database.Create(benchIsmDbType, dbPath, benchIsmBlockDataNet)
	if err != nil {
		b.Errorf("Failed to create test database (%s) %v", ismDbType, err)
		return
	}
	defer os.RemoveAll(dbPath)

	b.Log("testing ISM state")

	// create indexer and test
	ismState := NewState()
	idb.Update(func(tx database.Tx) error {
		ismState.Create(tx)

		b.Logf("testing to %v", b.N)

		i := 0
		for n := 0; n < b.N; n++ {
			StateOperations(numContracts, numItems, fmt.Sprintf("block_%v", i), tx, ismState)
			i++
		}

		return nil
	})

	idb.Close()
}

func BenchmarkISMState10_100(b *testing.B)     { benchmarkISMState(10, 100, b) }
func BenchmarkISMState100_1000(b *testing.B)   { benchmarkISMState(100, 1000, b) }
func BenchmarkISMState1000_10000(b *testing.B) { benchmarkISMState(1000, 10000, b) }
func BenchmarkISMState1_10000000(b *testing.B) { benchmarkISMState(1, 10000000, b) }
