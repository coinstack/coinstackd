// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"sync"

	"github.com/coinstack/coinstackd/blockchain"
	"github.com/coinstack/coinstackd/chaincfg"
	"github.com/coinstack/coinstackd/database"
	"github.com/coinstack/coinstackd/txscript"
	"github.com/coinstack/coinstackd/wire"
	"github.com/coinstack/btcutil"
)

const (
	utxoIndexName = "utxo index"
)

var (
	utxoIndexKey = []byte("utxoidx")
)

type UtxoIndex struct {
	mempoolAddrOutputIndex map[string](map[wire.OutPoint]*Output)
	mempoolLock            sync.RWMutex
	chainParams            *chaincfg.Params
}

type Output struct {
	TxHash   *wire.ShaHash // 32 bytes
	Vout     uint32        // 4 bytes
	Amount   int64         // 8 bytes
	Height   int32         // 4 bytes
	Coinbase bool          // 2 byte
	Script   []byte        // extra length
}

func serializeKey(outpoint *wire.OutPoint) []byte {
	key := make([]byte, 36)
	copy(key[0:32], outpoint.Hash.Bytes()[:])
	byteOrder.PutUint32(key[32:], outpoint.Index)
	return key
}

func serializeUtxoIndexEntry(entry *Output) []byte {
	serialized := make([]byte, 50+len(entry.Script))
	copy(serialized[0:32], entry.TxHash.Bytes()[:])
	byteOrder.PutUint32(serialized[32:], entry.Vout)
	byteOrder.PutUint64(serialized[36:], uint64(entry.Amount))
	byteOrder.PutUint32(serialized[44:], uint32(entry.Height))
	if entry.Coinbase {
		byteOrder.PutUint16(serialized[48:], uint16(0))
	} else {
		byteOrder.PutUint16(serialized[48:], uint16(1))
	}
	copy(serialized[50:], entry.Script)
	return serialized
}

func deserializeUtxoIndexEntry(serialized []byte, entry *Output) error {
	if len(serialized) < 50 {
		return errDeserialize("unexpected end of data")
	}

	hash := make([]byte, 32)
	copy(hash[0:32], serialized[0:32])

	entry.TxHash, _ = wire.NewShaHash(hash)
	entry.Vout = byteOrder.Uint32(serialized[32:36])
	entry.Amount = int64(byteOrder.Uint64(serialized[36:44]))
	entry.Height = int32(byteOrder.Uint32(serialized[44:48]))

	coinbaseFlag := byteOrder.Uint16(serialized[48:50])
	if coinbaseFlag == 0 {
		entry.Coinbase = true
	} else {
		entry.Coinbase = false
	}

	entry.Script = make([]byte, len(serialized)-50)
	copy(entry.Script, serialized[50:])

	return nil
}

// Ensure the UtxoIndex type implements the Indexer interface.
var _ Indexer = (*UtxoIndex)(nil)

func (idx *UtxoIndex) Init(bestHeight int32) error {
	// Nothing to do.
	return nil
}

func (idx *UtxoIndex) Key() []byte {
	return utxoIndexKey
}

func (idx *UtxoIndex) Name() string {
	return utxoIndexName
}

func (idx *UtxoIndex) Create(dbTx database.Tx) error {
	_, err := dbTx.Metadata().CreateBucket(utxoIndexKey)
	if nil != err {
		return err
	}
	return nil
}

func (idx *UtxoIndex) ConnectBlock(dbTx database.Tx, block *btcutil.Block, view *blockchain.UtxoViewpoint) error {
	for txIdx, tx := range block.Transactions() {
		if txIdx != 0 {
			for _, txIn := range tx.MsgTx().TxIn {
				origin := &txIn.PreviousOutPoint
				entry := view.LookupEntry(&origin.Hash)
				if entry == nil {
					continue
				}

				pkScript := entry.PkScriptByIndex(origin.Index)
				// mark outputs
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript,
					idx.chainParams)
				if nil != err {
					continue
				}
				key := createKey(&origin.Hash, origin.Index)
				for _, addr := range addrs {
					idx.markOutput(dbTx, key, addr.EncodeAddress())
				}
			}
		}

		for vout, txOut := range tx.MsgTx().TxOut {
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript,
				idx.chainParams)
			if err != nil {
				continue
			}

			for _, addr := range addrs {
				err := idx.addOutput(dbTx, tx.Sha(), uint32(vout), txOut.Value, addr.EncodeAddress(), block.Height(), txIdx == 0, txOut.PkScript)
				if nil != err {
					return err
				}
			}
		}
	}

	return nil
}

func (idx *UtxoIndex) DisconnectBlock(dbTx database.Tx, block *btcutil.Block, view *blockchain.UtxoViewpoint) error {
	for txIdx, tx := range block.Transactions() {
		// Coinbases do not reference any inputs.  Since the block is
		// required to have already gone through full validation, it has
		// already been proven on the first transaction in the block is
		// a coinbase.
		if txIdx != 0 {
			for _, txIn := range tx.MsgTx().TxIn {
				// The view should always have the input since
				// the index contract requires it, however, be
				// safe and simply ignore any missing entries.
				origin := &txIn.PreviousOutPoint
				entry := view.LookupEntry(&origin.Hash)
				if entry == nil {
					continue
				}

				pkScript := entry.PkScriptByIndex(origin.Index)
				// mark outputs
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript,
					idx.chainParams)
				if nil != err {
					continue
				}
				for _, addr := range addrs {
					err := idx.addOutput(dbTx, &origin.Hash, uint32(origin.Index), entry.AmountByIndex(origin.Index), addr.EncodeAddress(), block.Height(), txIdx == 0, pkScript)
					if nil != err {
						return err
					}
				}
			}
		}

		for vout, txOut := range tx.MsgTx().TxOut {
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript,
				idx.chainParams)
			if err != nil {
				continue
			}

			key := createKey(tx.Sha(), uint32(vout))

			for _, addr := range addrs {
				err := idx.markOutput(dbTx, key, addr.EncodeAddress())
				if nil != err {
					return err
				}
			}
		}
	}

	return nil
}

func (idx *UtxoIndex) AddUnconfirmedTx(tx *btcutil.Tx, view *blockchain.UtxoViewpoint, fetchTx func(txHash *wire.ShaHash) (*btcutil.Tx, bool)) {
	idx.mempoolLock.Lock()
	defer idx.mempoolLock.Unlock()

	for vout, txOut := range tx.MsgTx().TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript,
			idx.chainParams)
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			idx.addMempoolOutput(tx.Sha(), uint32(vout), txOut.Value, addr.EncodeAddress(), -1, false, txOut.PkScript)
		}
	}
}

func (idx *UtxoIndex) RemoveUnconfirmedTx(tx *btcutil.Tx) {
	idx.mempoolLock.Lock()
	defer idx.mempoolLock.Unlock()

	for vout, txOut := range tx.MsgTx().TxOut {
		_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript,
			idx.chainParams)
		if err != nil {
			continue
		}

		key := createKey(tx.Sha(), uint32(vout))

		for _, addr := range addrs {
			idx.markMempoolOutput(key, addr.EncodeAddress())
		}
	}
}

func createKey(txHash *wire.ShaHash, vout uint32) wire.OutPoint {
	return wire.OutPoint{Hash: *txHash, Index: vout}
}

func (idx *UtxoIndex) addOutput(dbTx database.Tx, txHash *wire.ShaHash, vout uint32, amount int64, addr string, height int32, isCoinbase bool, script []byte) error {
	utxoIdxBucket := dbTx.Metadata().Bucket(utxoIndexKey)
	outputMap, err := utxoIdxBucket.CreateBucketIfNotExists([]byte(addr))
	if nil != err {
		return err
	}
	key := createKey(txHash, vout)
	err = outputMap.Put(
		serializeKey(&key),
		serializeUtxoIndexEntry(&Output{
			TxHash:   txHash,
			Vout:     vout,
			Amount:   amount,
			Height:   height,
			Coinbase: isCoinbase,
			Script:   script,
		}))
	if nil != err {
		return err
	}
	return nil
}

func (idx *UtxoIndex) markOutput(dbTx database.Tx, outputKey wire.OutPoint, addr string) error {
	utxoIdxBucket := dbTx.Metadata().Bucket(utxoIndexKey)
	outputMap := utxoIdxBucket.Bucket([]byte(addr))
	if nil == outputMap {
		return nil // do nothing
	}
	err := outputMap.Delete(serializeKey(&outputKey))
	if nil != err {
		return err
	}

	return nil
}

func (idx *UtxoIndex) addMempoolOutput(txHash *wire.ShaHash, vout uint32, amount int64, addr string, height int32, isCoinbase bool, script []byte) {
	outputMap, hasKey := idx.mempoolAddrOutputIndex[addr]
	if !hasKey {
		outputMap = map[wire.OutPoint]*Output{}
		idx.mempoolAddrOutputIndex[addr] = outputMap
	}
	outputKey := createKey(txHash, vout)
	outputMap[outputKey] = &Output{
		TxHash:   txHash,
		Vout:     vout,
		Amount:   amount,
		Height:   height,
		Coinbase: isCoinbase,
		Script:   script,
	}
}

func (idx *UtxoIndex) markMempoolOutput(outputKey wire.OutPoint, addr string) {
	outputMap, hasKey := idx.mempoolAddrOutputIndex[addr]
	if !hasKey {
		return
	}
	delete(outputMap, outputKey)
}

func (idx *UtxoIndex) fetchOutputs(dbTx database.Tx, addr string) (mempoolUtxos map[wire.OutPoint]*Output, blockUtxos map[wire.OutPoint]*Output, err error) {
	blockUtxos = map[wire.OutPoint]*Output{}
	utxoIdxBucket := dbTx.Metadata().Bucket(utxoIndexKey)
	outputMap := utxoIdxBucket.Bucket([]byte(addr))
	if nil != outputMap {
		// fetch outputs
		err = outputMap.ForEach(func(key []byte, value []byte) error {
			var entry Output
			e := deserializeUtxoIndexEntry(value, &entry)
			blockUtxos[wire.OutPoint{Hash: *entry.TxHash, Index: entry.Vout}] = &entry
			return e
		})
		if nil != err {
			return nil, nil, err
		}
	}

	mempoolUtxos, hasKey := idx.mempoolAddrOutputIndex[addr]

	if !hasKey {
		mempoolUtxos = map[wire.OutPoint]*Output{}
	}

	return
}

func (idx *UtxoIndex) FetchOutputs(dbTx database.Tx, addr string) (mempoolUtxos map[wire.OutPoint]*Output, blockUtxos map[wire.OutPoint]*Output, err error) {
	return idx.fetchOutputs(dbTx, addr)
}

func NewUtxoIndex(chainParams *chaincfg.Params) *UtxoIndex {
	return &UtxoIndex{
		mempoolAddrOutputIndex: map[string](map[wire.OutPoint]*Output){},
		chainParams:            chainParams,
	}
}
