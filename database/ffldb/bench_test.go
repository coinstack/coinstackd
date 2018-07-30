// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ffldb

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coinstack/coinstackd/chaincfg"
	"github.com/coinstack/coinstackd/database"
	"github.com/coinstack/btcutil"
)

// BenchmarkBlockHeader benchmarks how long it takes to load the mainnet genesis
// block header.
func BenchmarkBlockHeader(b *testing.B) {
	// Start by creating a new database and populating it with the mainnet
	// genesis block.
	dbPath := filepath.Join(os.TempDir(), "ffldb-benchblkhdr")
	_ = os.RemoveAll(dbPath)
	db, err := database.Create("ffldb", dbPath, blockDataNet)
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(dbPath)
	defer db.Close()
	err = db.Update(func(tx database.Tx) error {
		block := btcutil.NewBlock(chaincfg.MainNetParams.GenesisBlock)
		if e := tx.StoreBlock(block); e != nil {
			return e
		}
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	err = db.View(func(tx database.Tx) error {
		blockHash := chaincfg.MainNetParams.GenesisHash
		for i := 0; i < b.N; i++ {
			_, e := tx.FetchBlockHeader(blockHash)
			if e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}

	// Don't benchmark teardown.
	b.StopTimer()
}

// BenchmarkBlockHeader benchmarks how long it takes to load the mainnet genesis
// block.
func BenchmarkBlock(b *testing.B) {
	// Start by creating a new database and populating it with the mainnet
	// genesis block.
	dbPath := filepath.Join(os.TempDir(), "ffldb-benchblk")
	_ = os.RemoveAll(dbPath)
	db, err := database.Create("ffldb", dbPath, blockDataNet)
	if err != nil {
		b.Fatal(err)
	}
	defer os.RemoveAll(dbPath)
	defer db.Close()
	err = db.Update(func(tx database.Tx) error {
		block := btcutil.NewBlock(chaincfg.MainNetParams.GenesisBlock)
		if e := tx.StoreBlock(block); e != nil {
			return e
		}
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	err = db.View(func(tx database.Tx) error {
		blockHash := chaincfg.MainNetParams.GenesisHash
		for i := 0; i < b.N; i++ {
			_, e := tx.FetchBlock(blockHash)
			if e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}

	// Don't benchmark teardown.
	b.StopTimer()
}
