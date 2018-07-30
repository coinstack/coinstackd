// Copyright (c) 2016 BLOCKO INC.
package indexers

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/coinstack/coinstackd/blockchain"
	"github.com/coinstack/coinstackd/chaincfg"
	"github.com/coinstack/coinstackd/database"
	"github.com/coinstack/coinstackd/txscript"
	"github.com/coinstack/coinstackd/wire"
	"github.com/coinstack/btcutil"
	"github.com/btcsuite/fastsha256"
)

const (
	dtIndexName = "delete tx index"
)

var (
	dtIndexKey = []byte("dtidx")
	dtAddrKey  = []byte("dtaddr")
)

var (
	DTMarker    = []byte{0x44, 0x55} // wire.DeletedTxMarker, DT
	DTVersion_1 = []byte{0x01, 0x00} // wire.DeletedTxVersion, v1.0
	DTVersion_2 = []byte{0x02, 0x00} // wire.DeletedTxVersion, v2.0
	DTOpTxID    = []byte{0x00, 0x01} // wire.DeletedTxOpTxID, 0x0001
	DTOpAddr    = []byte{0x00, 0x02} // wire.DeletedTxOpAddr, 0x0002

	DTFilterVersionSkip = []byte{0x00, 0x00}
)

type DTIndex struct {
	chainParams *chaincfg.Params
	chain       *blockchain.BlockChain
	addrIndex   *AddrIndex
	db          database.DB
}

func NewDTIndex(chainParams *chaincfg.Params, db database.DB, addrIndex *AddrIndex) *DTIndex {
	return &DTIndex{
		chainParams: chainParams,
		addrIndex:   addrIndex,
		db:          db,
	}
}
func (idx *DTIndex) SetChain(_chain *blockchain.BlockChain) {
	idx.chain = _chain
}
func (idx *DTIndex) GetChain() *blockchain.BlockChain {
	return idx.chain
}

// Ensure the DTIndex type implements the Indexer interface.
var _ Indexer = (*DTIndex)(nil)

func (idx *DTIndex) Key() []byte {
	return dtIndexKey
}
func (idx *DTIndex) Name() string {
	return dtIndexName
}
func (idx *DTIndex) Init(bestHeight int32) error {
	// Nothing to do.
	return nil
}
func (idx *DTIndex) Create(dbTx database.Tx) error {
	// create root bucket
	dtIdxBucket, err := dbTx.Metadata().CreateBucket(dtIndexKey)
	if err != nil {
		return err
	}

	// create address bucket under the root bucket
	_, err = dtIdxBucket.CreateBucket(dtAddrKey)
	return err
}
func (idx *DTIndex) DisconnectBlock(dbTx database.Tx, block *btcutil.Block, view *blockchain.UtxoViewpoint) error {
	// Nothing to do.
	return nil
}
func (idx *DTIndex) ConnectBlock(dbTx database.Tx, block *btcutil.Block, view *blockchain.UtxoViewpoint) error {
	// handle genesis block
	if block.Sha().IsEqual(idx.chainParams.GenesisHash) {
		return nil // discard genesis block
	}
	for _, tx := range block.Transactions() {
		err := idx.processTx(dbTx, block, tx, view)
		if err != nil {
			log.Debug("dtidx: processTx failed. err=", err)
			// skip, do nothing
		}
	}
	return nil
}
func (idx *DTIndex) processTx(dbTx database.Tx, block *btcutil.Block, tx *btcutil.Tx, view *blockchain.UtxoViewpoint) error {
	mtx := tx.MsgTx()
	payload := parseTx(mtx)
	if payload == nil {
		// data output not found
		return nil
	}
	if len(payload) <= 6 {
		// data output is too short to contain marker and metadata
		return nil
	}
	markerBytes := payload[0:2]
	versionBytes := payload[2:4]
	opCodeBytes := payload[4:6]
	if !bytes.Equal(markerBytes, DTMarker) {
		// Marker Not Found
		//log.Debug("marker magic byte not found: tx=", mtx.TxSha().String())
		return nil
	}

	if !(bytes.Equal(versionBytes, DTVersion_1) || bytes.Equal(versionBytes, DTVersion_2)) {
		// invalid version
		return nil
	}

	log.Trace("dtidx.processTx: marker magic byte found: tx=",
		mtx.TxSha().String(), ", payload[0:6]=", hex.EncodeToString(payload[0:6]))

	metadata, err := parsePayloadBody(payload[6:])
	if err != nil {
		return err
	}
	if bytes.Equal(opCodeBytes, DTOpTxID) {
		return idx.processDeleteTxID(dbTx, block, mtx, DTOpTxID, metadata)
	} else if bytes.Equal(opCodeBytes, DTOpAddr) {
		return idx.processDeleteAddr(dbTx, block, mtx, DTOpAddr, metadata)
	}
	log.Debug("dtidx.processTx: invalid opCode parameters, opCode=", hex.EncodeToString(opCodeBytes))
	return nil
}

func parseTx(mtx *wire.MsgTx) []byte {
	i, to := mtx.GetDataOut()
	if i < 0 {
		// data output not found
		return nil
	}
	// Parse PkScript of TxOut
	parsedScript, err := txscript.ParseScript(to.PkScript)
	if err != nil {
		// Since marker output has no parsable script, ignore tx
		return nil
	}
	// Check if script has at least components
	if len(parsedScript) < 2 {
		return nil
	}
	payload := parsedScript[1].Data
	return payload
}
func parsePayloadBody(body []byte) ([]byte, error) {
	dataReader := bytes.NewReader(body)

	hash, err := readVarBytes(dataReader)
	if err != nil {
		return nil, err
	}

	metadata, err := readVarBytes(dataReader)
	if err != nil {
		return nil, err
	}

	err = validateMetadata(hash, metadata)
	if err != nil {
		return nil, err
	}
	return metadata, err
}
func validateMetadata(hashBytes, metadata []byte) error {
	hasher := fastsha256.New()
	_, err := hasher.Write(metadata)
	if err != nil {
		return err
	}
	hashed := hasher.Sum(nil)
	if !bytes.Equal(hashBytes, hashed) {
		return fmt.Errorf("invalid hash for metadata")
	}
	return nil
}
func (idx *DTIndex) parseMetadata(opcode, metadata []byte) (*DtAddrMetadata, error) {
	reader := bytes.NewReader(metadata)
	blockHeight, err := readInt32(reader)
	if err != nil {
		return nil, err
	}

	address, err := readVarString(reader)
	if err != nil {
		return nil, err
	}
	filter, err := readVarBytes(reader)
	if err != nil {
		return nil, err
	}
	return NewDtAddrMetadata(idx.chainParams, opcode, blockHeight, address, filter)
}

func readInt32(reader *bytes.Reader) (int32, error) {
	var buf int32
	err := binary.Read(reader, binary.BigEndian, &buf)
	if err != nil {
		return -1, err
	}
	return buf, nil
}
func readVarString(reader *bytes.Reader) (string, error) {
	buf, err := readVarBytes(reader)
	if err != nil {
		return "", err
	}
	return string(buf), err
}
func readVarBytes(reader *bytes.Reader) ([]byte, error) {
	size, err := readInt32(reader)
	if err != nil {
		return nil, err
	}
	if size <= 0 {
		return nil, fmt.Errorf("size of variable bytes is less than zero. size=%d", size)
	}
	if size > int32(reader.Len()) {
		return nil, fmt.Errorf("not enough readable portion of bytes, size=%d, reader.len=%d", size, reader.Len())
	}
	buf := make([]byte, size)
	_, err = reader.Read(buf)
	return buf, err
}

func (idx *DTIndex) processDeleteTxID(dbTx database.Tx, block *btcutil.Block, mtx *wire.MsgTx, opcode, metadata []byte) error {
	// deprecated, do nothing
	// - check master permission
	// - get msg.Tx from db
	// - DeleteTx(msg.Tx)
	return nil
}
func (idx *DTIndex) processDeleteAddr(dbTx database.Tx, block *btcutil.Block, mtx *wire.MsgTx, opCode, metadata []byte) error {
	currBlockHeight := block.Height()
	addrMeta, err := idx.parseMetadata(opCode, metadata)
	log.Debugf("dtidx.processDeleteAddr: currBlockHeight=%d, blockHeight=%d, address=%s, filter=%s",
		currBlockHeight, addrMeta.BlockHeight,
		addrMeta.Address, hex.EncodeToString(addrMeta.Filter))
	if err != nil {
		return err
	}

	if addrMeta.BlockHeight >= currBlockHeight {
		// invalid block height
		return fmt.Errorf("invalid block height to delete tx. blockHeight=%d, expected to be greater than currentBlockHeight=%d",
			addrMeta.BlockHeight, currBlockHeight)
	}

	return idx.deleteAddressHistory(dbTx, addrMeta)
}

type DtAddrMetadata struct {
	OpCode      []byte
	BlockHeight int32
	Address     btcutil.Address
	Filter      []byte
}

func NewDtAddrMetadata(chainParams *chaincfg.Params, opCode []byte, blockHeight int32, address string, filter []byte) (*DtAddrMetadata, error) {
	addr, err := btcutil.DecodeAddress(address, chainParams)
	if err != nil {
		return nil, err
	}
	return &DtAddrMetadata{
		OpCode:      opCode,
		BlockHeight: blockHeight,
		Address:     addr,
		Filter:      filter,
	}, nil
}
func (meta *DtAddrMetadata) Key() []byte {
	key := meta.Address.ScriptAddress()
	return append(key, meta.Filter...)
}

type DtAddrBucketValue struct {
	BlockHeight uint32
	NumToSkip   uint32
}

func (val *DtAddrBucketValue) Encode(w io.Writer) error {
	err := binary.Write(w, binary.LittleEndian, val.BlockHeight)
	if err != nil {
		return err
	}
	err = binary.Write(w, binary.LittleEndian, val.NumToSkip)
	return err
}
func (val *DtAddrBucketValue) Decode(r io.Reader) error {
	err := binary.Read(r, binary.LittleEndian, &val.BlockHeight)
	if err != nil {
		return err
	}
	err = binary.Read(r, binary.LittleEndian, &val.NumToSkip)
	return err
}
func bucketGetValue(bucket *database.Bucket, key []byte) (*DtAddrBucketValue, error) {
	v := DtAddrBucketValue{}
	buf := (*bucket).Get(key)
	if buf == nil {
		return &v, fmt.Errorf("nothing to return for the key")
	}
	err := v.Decode(bytes.NewBuffer(buf))
	return &v, err
}
func bucketPutValue(bucket *database.Bucket, key []byte, v *DtAddrBucketValue) error {
	buf := new(bytes.Buffer)
	err := v.Encode(buf)
	if err != nil {
		return err
	}
	ret := buf.Bytes()
	err = (*bucket).Put(key, ret)
	return err
}

func (idx *DTIndex) deleteAddressHistory(dbTx database.Tx, addrMeta *DtAddrMetadata) error {
	log.Debugf("dtidx.deleteAddressHistory: blockHeight=%d, address=%s, filter=%s",
		addrMeta.BlockHeight, addrMeta.Address.String(), hex.EncodeToString(addrMeta.Filter))

	// TODO: read numToSkip from dtidx
	dtAddrBucket := dbTx.Metadata().Bucket(dtIndexKey).Bucket(dtAddrKey)
	metaKey := addrMeta.Key()
	v, _ := bucketGetValue(&dtAddrBucket, metaKey)

	if addrMeta.BlockHeight <= int32(v.BlockHeight) {
		// already deleted, do nothing
		return fmt.Errorf("already deleted, blockHeight is %d, expected greater than previous %d",
			addrMeta.BlockHeight, v.BlockHeight)
	}

	numRequested := -1
	reverse := false
	var txIDs []wire.ShaHash
	err := idx.db.View(func(dbTx database.Tx) error {
		var err error
		txIDs, _, err = idx.addrIndex.TxIDsForAddress(dbTx, addrMeta.Address, v.NumToSkip, uint32(numRequested), reverse)
		return err
	})
	if err != nil {
		return err
	}

	var blockHeadersBytes [][]byte
	var txsBytes [][]byte
	err = idx.db.View(func(dbTx database.Tx) error {
		var e error
		blockHeadersBytes, txsBytes, e = dbTx.FetchTransactions(txIDs)
		return e
	})
	if err != nil {
		return err
	}

	var skipCount = 0
	var delCount = 0
	for i, v := range txsBytes {
		var msgTx wire.MsgTx
		e := msgTx.Deserialize(bytes.NewReader(v))
		if e != nil {
			return e
		}
		txBlockHeight, _, e := getBlockHeader(blockHeadersBytes[i], idx.GetChain())
		if e != nil {
			return e
		}
		log.Tracef("tx=%s, height=%d", msgTx.TxSha().String(), txBlockHeight)
		if txBlockHeight > addrMeta.BlockHeight {
			delCount++
			break
		}
		// txBlockHeight <= addrMeta.BlockHeight
		success, e := DeleteTxFromDb(dbTx, &msgTx, addrMeta.OpCode, addrMeta.Filter)
		if e != nil {
			return e
		}
		if !success {
			skipCount++
			continue
		}
	}

	newval := DtAddrBucketValue{
		BlockHeight: uint32(addrMeta.BlockHeight),
		NumToSkip:   v.NumToSkip + uint32(skipCount) + uint32(delCount),
	}
	err = bucketPutValue(&dtAddrBucket, metaKey, &newval)
	return err
}
func DeleteTxFromDb(dbTx database.Tx, msgTx *wire.MsgTx, opCode, filter []byte) (bool, error) {
	msgTx, err := deleteTx(msgTx, opCode, filter)
	if err != nil {
		return false, err
	}
	if msgTx == nil {
		// not deletable, skip
		return false, nil
	}
	exists, err := dbTx.UpdateTransaction(msgTx)
	if !exists {
		return false, fmt.Errorf("Failed to update transaction, tx not exists, txId=%s", msgTx.TxSha().String())
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func getBlockHeader(blockHeaderBytes []byte, chain *blockchain.BlockChain) (int32, *wire.ShaHash, error) {
	// Deserialize the header.
	var header wire.BlockHeader
	err := header.Deserialize(bytes.NewReader(blockHeaderBytes))
	if err != nil {
		context := "Failed to deserialize block header"
		return 0, nil, errors.New(context)
	}
	// Grab the block height.
	hash := header.BlockSha()
	height, err := chain.BlockHeightByHash(&hash)
	if err != nil {
		context := "Failed to retrieve block height"
		return 0, &hash, errors.New(context)
	}
	return height, &hash, nil
}

func deleteTx(msg *wire.MsgTx, opCode, filter []byte) (*wire.MsgTx, error) {
	i, to := msg.GetDataOut()
	if i < 0 {
		// data output not found
		return nil, nil
	}
	if !to.IsDeletable() {
		return nil, nil
	}
	// Parse PkScript of TxOut
	parsedScript, err := txscript.ParseScript(to.PkScript)
	if err != nil {
		return nil, nil
	}
	// Check if script has at least components
	if len(parsedScript) < 2 {
		return nil, nil
	}
	payload := parsedScript[1].Data
	if len(filter) > 0 && !matchPayloadFilter(payload, filter) {
		// filter not matched
		return nil, nil
	}

	// tx del script
	td, delScript, err := genTxDelScript(opCode, len(payload), msg)
	if err != nil {
		return nil, err
	}
	to.PkScript = delScript
	msg.TxDel = td
	return msg, nil
}
func matchPayloadFilter(payload []byte, filter []byte) bool {
	if len(payload) < len(filter) {
		// not matched. payload length is shorter than filter.
		return false
	}
	if len(filter) == 6 && bytes.Equal(filter[2:4], DTFilterVersionSkip) {
		// check marker and op, without version
		return bytes.Equal(filter[0:2], payload[0:2]) && bytes.Equal(filter[4:6], payload[4:6])
	}
	return bytes.HasPrefix(payload, filter)
}
func genTxDelScript(opCode []byte, payloadSize int, msg *wire.MsgTx) (*wire.TxDel, []byte, error) {
	msgTxHash := msg.TxSha()
	sigHash := msg.TxSigHash(msgTxHash.Bytes())
	td := wire.NewTxDel(&msgTxHash, &sigHash)
	payload := td.Payload(opCode, payloadSize)
	script, err := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN).
		AddFullData(payload).Script()
	return td, script, err
}
