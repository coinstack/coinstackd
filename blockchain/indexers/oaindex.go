// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"github.com/coinstack/coinstackd/blockchain"
	"github.com/coinstack/coinstackd/blockchain/indexers/openassets"
	"github.com/coinstack/coinstackd/chaincfg"
	"github.com/coinstack/coinstackd/database"
	"github.com/coinstack/coinstackd/wire"
	"github.com/coinstack/btcutil"
)

const (
	oaIndexName = "open assets index"
)

var (
	oaIndexKey = []byte("oaidx")
)

type OAIndex struct {
	mempoolOAOutputIndex map[string]([]*openassets.Meta)
	db                   database.DB
	chainParams          *chaincfg.Params
}

// Ensure the OAIndex type implements the Indexer interface.
var _ Indexer = (*OAIndex)(nil)

func (idx *OAIndex) Init(bestHeight int32) error {
	// Nothing to do.
	return nil
}

func (idx *OAIndex) Key() []byte {
	return oaIndexKey
}

func (idx *OAIndex) Name() string {
	return oaIndexName
}

func (idx *OAIndex) Create(dbTx database.Tx) error {
	_, err := dbTx.Metadata().CreateBucket(oaIndexKey)
	if nil != err {
		return err
	}
	return nil
}

func (idx *OAIndex) ConnectBlock(dbTx database.Tx, block *btcutil.Block, view *blockchain.UtxoViewpoint) error {
	// handle genesis block
	if block.Sha().IsEqual(idx.chainParams.GenesisHash) {
		return nil // discard genesis block
	}

	for _, tx := range block.Transactions() {
		idx.processTx(dbTx, tx, view, true)
	}

	return nil
}

func (idx *OAIndex) DisconnectBlock(dbTx database.Tx, block *btcutil.Block, view *blockchain.UtxoViewpoint) error {
	for _, tx := range block.Transactions() {
		idx.unprocessTx(dbTx, tx, view)
	}

	return nil
}

func (idx *OAIndex) AddUnconfirmedTx(tx *btcutil.Tx, view *blockchain.UtxoViewpoint) {
	_ = idx.db.View(func(dbTx database.Tx) error {
		idx.processTx(dbTx, tx, view, false)
		return nil
	})
}

func (idx *OAIndex) RemoveUnconfirmedTx(tx *wire.ShaHash) {
	idx.removeUnconfirmedMeta(tx)
}

func (idx *OAIndex) processTx(dbTx database.Tx, tx *btcutil.Tx, view *blockchain.UtxoViewpoint, confirmed bool) error {
	if len(tx.MsgTx().TxOut) < 2 {
		return nil // ignore tx
	}

	outputCount := int32(len(tx.MsgTx().TxOut))
	for outputIndex, txOut := range tx.MsgTx().TxOut {
		markerMeta, ok := openassets.ParseMarkerOutput(txOut, int32(outputIndex), outputCount)
		if ok {
			// fetch existing meta for inputs
			inputMeta := make([]*openassets.Meta, len(tx.MsgTx().TxIn))
			// populate input meta
			for inputIndex, txIn := range tx.MsgTx().TxIn {
				previousMeta := idx.fetchMeta(dbTx, &txIn.PreviousOutPoint.Hash)
				if previousMeta == nil {
					previousMeta = idx.fetchUnconfirmedMeta(&txIn.PreviousOutPoint.Hash)
				}
				if previousMeta != nil {
					inputMeta[inputIndex] = previousMeta[txIn.PreviousOutPoint.Index]
				} else {
					inputMeta[inputIndex] = &openassets.Meta{
						OutputType: openassets.MetaUncolored,
					}
				}
			}
			issuanceSource := view.LookupEntry(&tx.MsgTx().TxIn[0].PreviousOutPoint.Hash)
			if issuanceSource == nil {
				continue
			}
			pkScript := issuanceSource.PkScriptByIndex(tx.MsgTx().TxIn[0].PreviousOutPoint.Index)
			inputMeta[0].Script = pkScript
			// TODO: optimize by caching/batching

			outputMeta, isOA := openassets.AssignQuantities(tx.MsgTx(), inputMeta, markerMeta)
			if isOA {
				if confirmed {
					// record output meta
					err := idx.saveMeta(dbTx, tx.Sha(), outputMeta)
					if nil != err {
						return err
					}
				} else {
					idx.saveUnconfirmedMeta(tx.Sha(), outputMeta)
				}
			}
		}
	}

	return nil
}

func (idx *OAIndex) unprocessTx(dbTx database.Tx, tx *btcutil.Tx, view *blockchain.UtxoViewpoint) error {
	// Check output for Open Access Controls
	if len(tx.MsgTx().TxOut) < 2 {
		return nil // ignore tx
	}

	return nil
}

func serializeOAIndexEntry(entries []*openassets.Meta) []byte {
	serialized := make([]byte, 34*len(entries))
	for i, entry := range entries {
		offset := i * 34
		byteOrder.PutUint16(serialized[offset:], uint16(entry.OutputType))
		byteOrder.PutUint16(serialized[offset+2:], entry.MajorVersion)
		byteOrder.PutUint16(serialized[offset+4:], entry.MinorVersion)
		byteOrder.PutUint64(serialized[offset+6:], entry.Quantity)
		copy(serialized[offset+14:], entry.AssetID)
	}
	return serialized
}

func deserializeOAIndexEntry(serialized []byte, entries *[]*openassets.Meta) {
	numItems := len(serialized) / 34
	*entries = make([]*openassets.Meta, numItems)

	for i := 0; i < numItems; i++ {
		offset := i * 34
		entry := openassets.Meta{}
		entry.OutputType = openassets.MetaType(byteOrder.Uint16(serialized[offset : offset+2]))
		entry.MajorVersion = byteOrder.Uint16(serialized[offset+2 : offset+4])
		entry.MinorVersion = byteOrder.Uint16(serialized[offset+4 : offset+6])
		entry.Quantity = byteOrder.Uint64(serialized[offset+6 : offset+14])
		entry.AssetID = make([]byte, 20)
		copy(entry.AssetID, serialized[offset+14:offset+34])
		(*entries)[i] = &entry
	}
}

func (idx *OAIndex) saveMeta(dbTx database.Tx, txHash *wire.ShaHash, outputMeta []*openassets.Meta) error {
	oaIdxBucket := dbTx.Metadata().Bucket(oaIndexKey)
	err := oaIdxBucket.Put(
		txHash.Bytes(), serializeOAIndexEntry(outputMeta))
	if nil != err {
		return err
	}
	return nil
}

func (idx *OAIndex) removeMeta(dbTx database.Tx, txHash *wire.ShaHash, outputMeta []*openassets.Meta) error {
	oaIdxBucket := dbTx.Metadata().Bucket(oaIndexKey)
	err := oaIdxBucket.Delete(txHash.Bytes())
	if nil != err {
		return err
	}
	return nil
}

func (idx *OAIndex) saveUnconfirmedMeta(txHash *wire.ShaHash, outputMeta []*openassets.Meta) error {
	idx.mempoolOAOutputIndex[txHash.String()] = outputMeta
	return nil
}

func (idx *OAIndex) removeUnconfirmedMeta(txHash *wire.ShaHash) error {
	delete(idx.mempoolOAOutputIndex, txHash.String())
	return nil
}

func (idx *OAIndex) fetchMeta(dbTx database.Tx, txHash *wire.ShaHash) []*openassets.Meta {
	oaIdxBucket := dbTx.Metadata().Bucket(oaIndexKey)
	serializedMeta := oaIdxBucket.Get(txHash.Bytes())
	if nil == serializedMeta {
		return nil
	}
	var meta []*openassets.Meta
	deserializeOAIndexEntry(serializedMeta, &meta)

	return meta
}

func (idx *OAIndex) fetchUnconfirmedMeta(txHash *wire.ShaHash) []*openassets.Meta {
	meta, ok := idx.mempoolOAOutputIndex[txHash.String()]

	if !ok {
		return nil
	}

	return meta
}

func (idx *OAIndex) FetchMeta(dbTx database.Tx, txHash *wire.ShaHash) []*openassets.Meta {
	return idx.fetchMeta(dbTx, txHash)
}

func (idx *OAIndex) FetchUnconfirmedMeta(txHash *wire.ShaHash) []*openassets.Meta {
	return idx.fetchUnconfirmedMeta(txHash)
}

func NewOAIndex(chainParams *chaincfg.Params, db database.DB) *OAIndex {
	return &OAIndex{
		chainParams:          chainParams,
		db:                   db,
		mempoolOAOutputIndex: make(map[string]([]*openassets.Meta)),
	}
}

type MempoolOAIndexer interface {
	AddUnconfirmedTx(tx *btcutil.Tx, view *blockchain.UtxoViewpoint)
	RemoveUnconfirmedTx(tx *wire.ShaHash)
}

type NoOpMempoolOAIndex struct{}

func (*NoOpMempoolOAIndex) AddUnconfirmedTx(tx *btcutil.Tx, view *blockchain.UtxoViewpoint) {
	return
}

func (*NoOpMempoolOAIndex) RemoveUnconfirmedTx(tx *wire.ShaHash) {
	return
}
