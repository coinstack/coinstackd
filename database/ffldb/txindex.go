// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ffldb

import (
	"fmt"

	"github.com/coinstack/coinstackd/database"
	"github.com/coinstack/coinstackd/wire"
	"github.com/coinstack/btcutil"
)

var (
	// txIndexKey is the key of the transaction index and the db bucket used
	// to house it.
	txIndexKey = []byte("txbyhashidx")

	txLocSize = 4 + 4 + 4 + 4
)

// -----------------------------------------------------------------------------
// The transaction index consists of an entry for every transaction in the main
// chain.  In order to significanly optimize the space requirements a separate
// index which provides an internal mapping between each block that has been
// indexed and a unique ID for use within the hash to location mappings.  The ID
// is simply a sequentially incremented uint32.  This is useful because it is
// only 4 bytes versus 32 bytes hashes and thus saves a ton of space in the
// index.
//
// There are three buckets used in total.  The first bucket maps the hash of
// each transaction to the specific block location.  The second bucket maps the
// hash of each block to the unique ID and the third maps that ID back to the
// block hash.
//
// NOTE: Although it is technically possible for multiple transactions to have
// the same hash as long as the previous transaction with the same hash is fully
// spent, this code only stores the most recent one because doing otherwise
// would add a non-trivial amount of space and overhead for something that will
// realistically never happen per the probability and even if it did, the old
// one must be fully spent and so the most likely transaction a caller would
// want for a given hash is the most recent one anyways.
//
// The serialized format for the keys and values in the tx index bucket is:
//
//   <txhash> = <block file num><start offset><tx length>
//
//   Field           Type            Size
//   txhash          wire.ShaHash    32 bytes
//   block file num  uint32          4 bytes
//   start offset    uint32          4 bytes
//   tx length       uint32          4 bytes
//   -----
//   Total: 44 bytes
// -----------------------------------------------------------------------------

// putTxIndexEntry serializes the provided values according to the format
// described about for a transaction index entry.  The target byte slice must
// be at least large enough to handle the number of bytes defined by the
// txEntrySize constant or it will panic.
func putTxIndexEntry(target []byte, blockFileNum uint32, blockOffset uint32, txLoc wire.TxLoc) {
	byteOrder.PutUint32(target, blockFileNum)
	byteOrder.PutUint32(target[4:], uint32(blockOffset))
	byteOrder.PutUint32(target[8:], uint32(txLoc.TxStart))
	byteOrder.PutUint32(target[12:], uint32(txLoc.TxLen))
}

// dbPutTxIndexEntry uses an existing database transaction to update the
// transaction index given the provided serialized data that is expected to have
// been serialized putTxIndexEntry.
func dbPutTxIndexEntry(dbTx database.Tx, txHash *wire.ShaHash, serializedData []byte) error {
	txIndex := dbTx.Metadata().Bucket(txIndexKey)
	return txIndex.Put(txHash[:], serializedData)
}

// dbFetchTxIndexEntry uses an existing database transaction to fetch the block
// region for the provided transaction hash from the transaction index.  When
// there is no entry for the provided hash, nil will be returned for the both
// the region and the error.
func dbFetchTxIndexEntry(dbTx database.Tx, txHash *wire.ShaHash) (*transactionLocation, error) {
	// Load the record from the database and return now if it doesn't exist.
	txIndex := dbTx.Metadata().Bucket(txIndexKey)
	serializedData := txIndex.Get(txHash[:])
	if len(serializedData) == 0 {
		return nil, nil
	}

	// Ensure the serialized data has enough bytes to properly deserialize.
	if len(serializedData) < 16 {
		return nil, database.Error{
			ErrorCode: database.ErrCorruption,
			Description: fmt.Sprintf("corrupt transaction index "+
				"entry for %s", txHash),
		}
	}

	// Deserialize the final entry.
	var txLoc transactionLocation
	txLoc.blockFileNum = byteOrder.Uint32(serializedData[0:4])
	txLoc.blockOffset = byteOrder.Uint32(serializedData[4:8])
	txLoc.txOffset = byteOrder.Uint32(serializedData[8:12])
	txLoc.txLen = byteOrder.Uint32(serializedData[12:16])

	return &txLoc, nil
}

// dbAddTxIndexEntries uses an existing database transaction to add a
// transaction index entry for every transaction in the passed block.
func dbAddTxIndexEntries(dbTx database.Tx, block *btcutil.Block, blockLoc blockLocation) error {
	// The offset and length of the transactions within the serialized
	// block.
	txLocs, err := block.TxLoc()
	if err != nil {
		return err
	}

	// As an optimization, allocate a single slice big enough to hold all
	// of the serialized transaction index entries for the block and
	// serialize them directly into the slice.  Then, pass the appropriate
	// subslice to the database to be written.  This approach significantly
	// cuts down on the number of required allocations.
	offset := 0
	serializedValues := make([]byte, len(block.Transactions())*txLocSize)
	for i, tx := range block.Transactions() {
		// serialize a location info
		putTxIndexEntry(serializedValues[offset:], blockLoc.blockFileNum,
			blockLoc.fileOffset, txLocs[i])
		endOffset := offset + txLocSize
		// put to the db
		err := dbPutTxIndexEntry(dbTx, tx.Sha(),
			serializedValues[offset:endOffset:endOffset])
		if err != nil {
			return err
		}
		offset += txLocSize
	}

	return nil
}

// dbRemoveTxIndexEntry uses an existing database transaction to remove the most
// recent transaction index entry for the given hash.
func dbRemoveTxIndexEntry(dbTx database.Tx, txHash *wire.ShaHash) error {
	txIndex := dbTx.Metadata().Bucket(txIndexKey)
	serializedData := txIndex.Get(txHash[:])
	if len(serializedData) == 0 {
		return fmt.Errorf("can't remove non-existent transaction %s "+
			"from the transaction index", txHash)
	}

	return txIndex.Delete(txHash[:])
}

// dbRemoveTxIndexEntries uses an existing database transaction to remove the
// latest transaction entry for every transaction in the passed block.
func dbRemoveTxIndexEntries(dbTx database.Tx, block *btcutil.Block) error {
	for _, tx := range block.Transactions() {
		err := dbRemoveTxIndexEntry(dbTx, tx.Sha())
		if err != nil {
			return err
		}
	}

	return nil
}

// Create is invoked when the indexer manager determines the index needs
// to be created for the first time.  It creates the buckets for the hash-based
// transaction index and the internal block ID indexes.
func initTxIndex(dbTx database.Tx) error {
	meta := dbTx.Metadata()

	_, err := meta.CreateBucket(txIndexKey)
	return err
}

// ConnectBlock is invoked by the index manager when a new block has been
// connected to the main chain.  This indexer adds a hash-to-transaction mapping
// for every transaction in the passed block.
//
// This is part of the Indexer interface.
func indexBlockTxs(dbTx database.Tx, block *btcutil.Block, location blockLocation) error {

	if err := dbAddTxIndexEntries(dbTx, block, location); err != nil {
		return err
	}

	// Add the new block ID index entry for the block being connected and
	// update the current internal block ID accordingly.
	/*
		err := dbPutBlockIDIndexEntry(dbTx, block.Sha(), newBlockID)
		if err != nil {
			return err
		}

		idx.curBlockID = newBlockID
	*/
	return nil
}

// disconnectBlockTxs is invoked by the index manager when a block has been
// disconnected from the main chain.  This indexer removes the
// hash-to-transaction mapping for every transaction in the block.
//
// This is part of the Indexer interface.
func disconnectBlockTxs(dbTx database.Tx, block *btcutil.Block) error {
	// Remove all of the transactions in the block from the index.
	if err := dbRemoveTxIndexEntries(dbTx, block); err != nil {
		return err
	}

	return nil
}

// TxBlockLocation returns the block region for the provided transaction hash
// from the transaction index.  The block region can in turn be used to load the
// raw transaction bytes.  When there is no entry for the provided hash, nil
// will be returned for the both the entry and the error.
//
// This function is safe for concurrent access.
func txBlockLocation(dbTx database.Tx, hash *wire.ShaHash) (*transactionLocation, error) {

	loc, err := dbFetchTxIndexEntry(dbTx, hash)

	return loc, err
}

// DropTxIndex drops the transaction index from the provided database if it
// exists.  Since the address index relies on it, the address index will also be
// dropped when it exists.
func DropTxIndex(db database.DB) error {
	// TODO implements
	// See manager.go:dropIndex()
	return database.Error{ErrorCode: database.ErrInvalid, Description: "Not Implemented", Err: nil}
}

// RebuildTxIndex drop and rebuild tx index
func RebuildTxIndex(db database.DB) error {
	// TODO implements
	// See manager.go:Init()
	return database.Error{ErrorCode: database.ErrInvalid, Description: "Not Implemented", Err: nil}
}
