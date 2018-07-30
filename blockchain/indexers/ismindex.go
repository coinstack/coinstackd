// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/coinstack/coinstackd/btcec"

	"encoding/json"

	"sync"

	"github.com/coinstack/coinstackd/blockchain"
	"github.com/coinstack/coinstackd/blockchain/indexers/ism"
	"github.com/coinstack/coinstackd/blockchain/indexers/opencontracts"
	"github.com/coinstack/coinstackd/chaincfg"
	"github.com/coinstack/coinstackd/coinstack/client"
	"github.com/coinstack/coinstackd/database"
	"github.com/coinstack/coinstackd/txscript"
	"github.com/coinstack/coinstackd/wire"
	"github.com/coinstack/btcutil"
)

const (
	indexName      = "immutable stored procedure index"
	undoStageCount = int32(1440)
)

var (
	ISMIndexKey        = []byte("ismidx")
	contractBodyKey    = []byte("body")
	contractTypeKey    = []byte("type")
	contractHashKey    = []byte("hash")
	errQuery           = errors.New("failed to execute the query")
	ErrNoContractFound = errors.New("no contract found")
)

type blockInformation struct {
	BlockHash      string
	BlockHeight    int32
	BlockTimestamp time.Time
	Confirmed      bool
}

type ISMIndex struct {
	chainParams         *chaincfg.Params
	db                  database.DB
	nodeGroupWIF        *btcutil.WIF
	nodeID              string
	ismState            *ism.State
	sqlState            ism.ISQLState
	disabledLStateCache bool
	EphemeralEnabled    bool
	PurgeOldUndoStage   bool
	lock                sync.RWMutex
	EphemeralLock       sync.RWMutex
}

type ISMQueryResult struct {
	Success bool             `json:"success"`
	Result  *json.RawMessage `json:"result,omitempty"`
	Error   *json.RawMessage `json:"error,omitempty"`
}

// Ensure the ISMIndex type implements the Indexer interface.
var _ Indexer = (*ISMIndex)(nil)

func (idx *ISMIndex) Init(bestHeight int32) error {
	if !idx.disabledLStateCache {
		idx.ismState.Init()
	}
	idx.db.Update(func(dbTx database.Tx) error {
		return idx.sqlState.Init(dbTx)
	})
	if idx.PurgeOldUndoStage {
		if purgingHeight := bestHeight - undoStageCount; purgingHeight > int32(0) {
			var hasUndoStage bool
			idx.db.View(func(dbTx database.Tx) error {
				hasUndoStage = idx.ismState.HasUndoStage(dbTx, purgingHeight)
				return nil
			})
			if hasUndoStage {
				for i := purgingHeight; i > int32(0); i-- {
					idx.db.Update(func(dbTx database.Tx) error {
						idx.ismState.PurgeStage(dbTx, i)
						return nil
					})
				}
			}
		}
	}
	return idx.db.Update(func(dbTx database.Tx) error {
		return idx.ismState.LoadEventListeners(dbTx)
	})
}

func (idx *ISMIndex) Key() []byte {
	return ISMIndexKey
}

func (idx *ISMIndex) Name() string {
	return indexName
}

func (idx *ISMIndex) Create(dbTx database.Tx) error {
	_, err := dbTx.Metadata().CreateBucket(ISMIndexKey)
	if err != nil {
		return err
	}

	return idx.ismState.Create(dbTx)
}

func (idx *ISMIndex) ConnectBlock(dbTx database.Tx, block *btcutil.Block, view *blockchain.UtxoViewpoint) error {
	connectStartTime := time.Now()
	defer func() {
		idx.ismState.Stat.Connect.AddDelta(connectStartTime)
	}()

	// handle genesis block
	if block.Sha().IsEqual(idx.chainParams.GenesisHash) {
		return nil // discard genesis block
	}

	// wait until all ephemeral transactions are processed as well
	log.Debugf("connecting a new block - %v", block.Sha().String())
	log.Debug("waiting connect block lock")

	if idx.EphemeralEnabled {
		idx.EphemeralLock.Lock()
		idx.lock.Lock()
		defer idx.lock.Unlock()
	}

	err := idx.ismState.NewStage(dbTx, block.Sha().Bytes())
	if err != nil {
		return err
	}
	err = idx.sqlState.NewStage(dbTx)
	if err != nil {
		return err
	}

	blockInfo := &blockInformation{
		BlockHeight:    block.Height(),
		BlockHash:      block.Sha().String(),
		BlockTimestamp: block.MsgBlock().Header.Timestamp,
		Confirmed:      true,
	}
	for _, tx := range block.Transactions() {
		idx.processTx(dbTx, blockInfo, tx, view)
	}

	if purgingHeight := block.Height() - undoStageCount; purgingHeight > int32(0) {
		idx.ismState.PurgeStage(dbTx, purgingHeight)
	}

	return idx.sqlState.CloseStage(dbTx)
}

func (idx *ISMIndex) DisconnectBlock(dbTx database.Tx, block *btcutil.Block, view *blockchain.UtxoViewpoint) error {
	if idx.EphemeralEnabled {
		idx.lock.Lock()
		defer idx.lock.Unlock()
	}
	err := idx.ismState.UndoStage(dbTx, block.Sha().Bytes(), block.MsgBlock().Header.PrevBlock.Bytes())
	if err != nil {
		return err
	}
	err = idx.sqlState.UndoStage(dbTx)
	if err != nil {
		return err
	}
	return nil
}

func NewISMIndex(
	chainParams *chaincfg.Params,
	db database.DB,
	ephemeral bool,
) *ISMIndex {
	ismState := ism.NewState()
	var sqlState ism.ISQLState
	if ephemeral {
		sqlState = ism.NewNullSQLState()
	} else {
		sqlState = ism.NewSQLState(ismState)
	}
	return &ISMIndex{
		chainParams: chainParams,
		db:          db,
		ismState:    ismState,
		sqlState:    sqlState,
	}
}

func (idx *ISMIndex) construeContractBody(body *opencontracts.Body) error {
	log.Tracef("contract body type: %v", body.Type)
	log.Tracef("contract body version: %v", body.Version)
	log.Tracef("contract body is encrypted: %v", body.Enc)

	if body.Version >= 1 {
		var eck []byte
		var err error

		// check ECK
		if body.Enc != 0 {
			log.Tracef("contract ECK list: %v", body.EEcks)

			// find the encrypt key (ECK) of "body"
			eck, err = opencontracts.FindECK(body.EEcks, idx.nodeGroupWIF, body.Version)
			if err != nil {
				log.Tracef("cannot be construed in this node:%v", err)
			}
		}

		// check whole code is encrypted
		if body.Enc == 10 {
			// if whole code is encrypted, decrypt "body"
			if eck == nil {
				return errors.New("cannot decipher contract body in this node")
			}

			body.Body, err = opencontracts.DecryptsCompat(body.Body, eck, body.Version)
			if err != nil {
				log.Debugf("cannot decipher contract body: %v", err)
				return fmt.Errorf("cannot decipher contract body: %v", err)
			}
		}

		// regenerate code with parameters
		code, err := opencontracts.RegenContractCode(body.Body, eck, body.Version)
		if err != nil {
			log.Debugf("fail to generate contract code: %v", err)
			return fmt.Errorf("fail to generate contract code: %v", err)
		}
		log.Tracef("generated contract code: %v", code)

		body.Body = []byte(code)
	} else {
		log.Tracef("contract code: %v", string(body.Body))
	}
	return nil
}

func (idx *ISMIndex) processOpencontract(dbTx database.Tx,
	block *blockInformation, tx *btcutil.Tx, view *blockchain.UtxoViewpoint,
	contractAddress string, markerMeta *opencontracts.Marker) error {
	log.Debug("processOpencontract")

	log.Tracef("contract payload: %v", markerMeta.RawPayload)
	log.Tracef("contract address: %v", contractAddress)

	contractConstructionStartTime := time.Now()
	err := idx.construeContractBody(&markerMeta.PayloadBody)
	idx.ismState.Stat.ConstrueContract.AddDelta(contractConstructionStartTime)
	if err != nil {
		return err
	}

	// look for Sender// Check input and ensure this tx is created by someone with permission
	senderExtractStartTime := time.Now()
	sender := ""
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
		for _, addr := range addrs {
			addrString := addr.EncodeAddress()
			if sender == "" {
				sender = addrString
			} else if sender != addrString {
				return errors.New("Contract invocation needs uniform issuers")
			}
		}
	}
	idx.ismState.Stat.SenderExtract.AddDelta(senderExtractStartTime)

	contractType := markerMeta.PayloadBody.Type

	switch markerMeta.OpCode {
	case opencontracts.Issuance:
		defStartTime := time.Now()
		defer func() {
			idx.ismState.Stat.Def.Total.AddDelta(defStartTime)
			idx.ismState.Stat.Def.Count++
		}()
		if !block.Confirmed {
			log.Trace("skipping issuance from unconfirmed tx")
			return nil
		}
		log.Tracef("op: issuance")
		if sender != contractAddress {
			return errors.New("Only original issuer can define contract")
		}

		if idx.ismState.HasInstance(dbTx, []byte(contractAddress)) {
			log.Tracef("redefining contract")
			idx.ismState.InvalidateContract([]byte(contractAddress))
		}

		if contractType == "LSC" {
			err = idx.issueLuaContract(dbTx, contractAddress, markerMeta)
		} else if contractType == "ESC" {
			idx.issueEthContract()
		} else {
			return errors.New("contract type unknown")
		}
		if err != nil {
			return err
		}

	case opencontracts.Execution:
		execStartTime := time.Now()
		defer func() {
			idx.ismState.Stat.Exec.Total.AddDelta(execStartTime)
			idx.ismState.Stat.Exec.Count++
		}()
		if !block.Confirmed {
			log.Trace("setting state to ephemeral for unconfirmed invocation")
			idx.ismState.NewEphemeralStage()
		}
		log.Tracef("op: execution")
		if !idx.ismState.HasInstance(dbTx, []byte(contractAddress)) {
			return errors.New("contract instance not initialized")
		}
		definition := idx.ismState.GetInstanceItem(dbTx, []byte(contractAddress), []byte(contractBodyKey))
		if definition == nil {
			return errors.New("contract issuance not foud")
		}

		if contractType == "LSC" {
			err := idx.executeLua(dbTx, markerMeta.PayloadBody.Body, contractAddress, definition, sender,
				block, tx, execStartTime, markerMeta)
			if nil != err {
				return err
			}
		} else if contractType == "ESC" {
			idx.executeEth()
		} else {
			return errors.New("contract type unknown")
		}
	case opencontracts.Termination:
		log.Tracef("op: termination")
	default:
		return errors.New("unrecognized opcode")
	}

	return nil
}

func (idx *ISMIndex) issueLuaContract(dbTx database.Tx, contractAddress string, markerMeta *opencontracts.Marker) error {
	// create new instance
	idx.ismState.CreateInstance(dbTx, []byte(contractAddress))
	err := idx.ismState.SetInstanceItem(dbTx, []byte(contractAddress), []byte(contractBodyKey), markerMeta.PayloadBody.Body)
	if err != nil {
		return err
	}
	err = idx.ismState.SetInstanceItem(dbTx, []byte(contractAddress), []byte(contractTypeKey), []byte(markerMeta.PayloadBody.Type))
	if err != nil {
		return err
	}
	err = idx.ismState.SetInstanceItem(dbTx, []byte(contractAddress), []byte(contractHashKey), []byte(markerMeta.PayloadHash))
	if err != nil {
		return err
	}
	return idx.ismState.Commit(dbTx, []byte(contractAddress))
}

func (idx *ISMIndex) issueEthContract() {
	return
}

func (idx *ISMIndex) executeLua(dbTx database.Tx, body []byte, contractAddress string, definition []byte, sender string,
	block *blockInformation, tx *btcutil.Tx, execStartTime time.Time,
	markerMeta *opencontracts.Marker) error {
	executor := ism.NewLuaExecutor(
		[]byte(contractAddress),
		idx.ismState,
		idx.sqlState,
		definition,
		&ism.ExecutorContext{
			Sender:      sender, // caller
			BlockHash:   block.BlockHash,
			BlockHeight: block.BlockHeight,
			Timestamp:   block.BlockTimestamp,
			Confirmed:   block.Confirmed,
			TxHash:      tx.Sha().String(),
			Node:        idx.nodeID,
		},
	)
	if executor == nil {
		return errors.New("failed to create contract executor")
	}
	idx.ismState.Stat.Exec.Prepare.AddDelta(execStartTime)
	startInitTime := time.Now()
	err := executor.Init(dbTx)
	if nil != err {
		return errors.New("failed to initialize contract")
	}
	idx.ismState.Stat.Exec.Init.AddDelta(startInitTime)
	defer executor.Finish()

	err = executor.Execute(dbTx, markerMeta.PayloadBody.Body)
	if nil != err {
		return errors.New("failed to invoke contract")
	}
	return nil
}

func (idx *ISMIndex) executeEth() {
	return
}

func (idx *ISMIndex) processTx(dbTx database.Tx, block *blockInformation, tx *btcutil.Tx, view *blockchain.UtxoViewpoint) error {
	if len(tx.MsgTx().TxOut) < 2 {
		return nil // ignore tx
	}

	contractAddress := ""

	// try to parse a second tx output
	parseMarkerOutputStartTime := time.Now()
	markerMeta, ok := opencontracts.ParseMarkerOutput(tx.MsgTx().TxOut[1])
	if !ok || markerMeta == nil {
		log.Trace("This is not an opencontract tx")
		return nil
	}

	idx.ismState.Stat.ParseMarkerOutput.AddDelta(parseMarkerOutputStartTime)

	for outputIndex, txOut := range tx.MsgTx().TxOut {
		if outputIndex == 0 {
			contractAddressExtractStartTime := time.Now()

			if markerMeta.MajorVersion == 1 {
				_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript,
					idx.chainParams)
				if nil != err {
					return errors.New("failed to parse contract address")
				}
				if len(addrs) < 1 {
					// ignore tx
					return errors.New("A first tx output for open contracts must contains target address using pay-to-pubkey or pay-to-script")
				}
				contractAddress = addrs[0].EncodeAddress()
			} else if markerMeta.MajorVersion == 2 {
				addr, err := txscript.ParseAddrDataScript(txOut.PkScript, idx.chainParams)
				if nil != err {
					return errors.New("failed to parse contract address")
				}
				contractAddress = addr.EncodeAddress()
			} else {
				log.Warn("Unknown contract version provided")

				return nil
			}

			idx.ismState.Stat.ContractIDExtract.AddDelta(contractAddressExtractStartTime)
		} else if outputIndex == 1 {
			err := idx.processOpencontract(dbTx, block, tx, view,
				contractAddress, markerMeta)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (idx *ISMIndex) FetchContractStatus(dbTx database.Tx, contractAddress string) (initialized bool, contractType string, contractHash string) {
	if idx.EphemeralEnabled {
		idx.lock.RLock()
		defer idx.lock.RUnlock()
	}

	log.Tracef("fetching contract for %v", contractAddress)
	instance := idx.ismState.GetInstance(dbTx, []byte(contractAddress))
	if instance == nil {
		log.Tracef("bucket for %v not found", contractAddress)
		return false, "", ""
	}

	contractType = string(instance.Get([]byte(contractTypeKey)))
	if contractType == "" {
		log.Tracef("type for %v not found", contractType)
		return false, "", ""
	}

	hash := instance.Get([]byte(contractHashKey))
	if hash == nil {
		log.Tracef("hash for %v not found", contractHash)
		return false, "", ""
	}

	return true, contractType, hex.EncodeToString(hash)
}

func (idx *ISMIndex) FetchContractGrantees(dbTx database.Tx, contractAddress string) []*client.ContractGrantee {
	if idx.EphemeralEnabled {
		idx.lock.RLock()
		defer idx.lock.RUnlock()
	}

	log.Tracef("fetching contract grantees for %v", contractAddress)

	grantees := []*client.ContractGrantee{}

	if !idx.ismState.HasInstance(dbTx, []byte(contractAddress)) {
		log.Tracef("bucket for %v not found", contractAddress)
		return grantees
	}

	iter := ism.NewPermissionIterator(idx.ismState, dbTx, contractAddress)
	if iter == nil {
		return grantees
	}

	permPrefixLen := len(ism.PermPrefix)
	for iter.Next() {
		if string(iter.Value()) != "1" {
			continue
		}
		if grantee := makeGrantee(iter.Key(), permPrefixLen); grantee != nil {
			grantees = append(grantees, grantee)
		}
	}

	return grantees
}

func (idx *ISMIndex) FetchContractStats() *client.ContractStat {
	if idx.EphemeralEnabled {
		idx.lock.RLock()
		defer idx.lock.RUnlock()
	}

	return &idx.ismState.Stat
}

func makeGrantee(key []byte, prefixLen int) *client.ContractGrantee {
	log.Tracef("makePermission: key=`%s`, prefixLen=%d", string(key), prefixLen)
	if len(key) <= prefixLen {
		return nil
	}
	grantee := key[prefixLen:]
	idx := bytes.IndexByte(grantee, '_')
	if idx == -1 || idx == len(grantee)-1 {
		return nil
	}
	token := grantee[idx+1:]
	grantee = grantee[:idx]
	return &client.ContractGrantee{
		Address: string(grantee),
		Token:   string(token),
	}
}

func (idx *ISMIndex) FetchContractSource(dbTx database.Tx, contractAddress string) (string, error) {
	if idx.EphemeralEnabled {
		idx.lock.RLock()
		defer idx.lock.RUnlock()
	}

	instance := idx.ismState.GetInstance(dbTx, []byte(contractAddress))
	if instance == nil {
		log.Trace("contract instance(%v) not found", contractAddress)
		return "", ErrNoContractFound
	}
	definition := instance.Get([]byte(contractBodyKey))
	if len(definition) == 0 {
		log.Trace("No definition found: contract id = %v", contractAddress)
		return "", ErrNoContractFound

	}
	return string(definition), nil
}

func (idx *ISMIndex) FetchContractFnSigs(dbTx database.Tx, contractAddress string) ([]*client.ContractFnSig, error) {
	if idx.EphemeralEnabled {
		idx.lock.RLock()
		defer idx.lock.RUnlock()
	}

	instance := idx.ismState.GetInstance(dbTx, []byte(contractAddress))
	if instance == nil {
		log.Trace("contract instance(%v) not found", contractAddress)
		return nil, ErrNoContractFound
	}

	definition := instance.Get([]byte(contractBodyKey))
	if len(definition) == 0 {
		log.Warnf("No definition found: contract id = %v", contractAddress)
		return nil, ErrNoContractFound

	}
	return idx.makeFnSigs(dbTx, []byte(contractAddress), definition)
}

func (idx *ISMIndex) makeFnSigs(dbTx database.Tx, contractAddress, definition []byte) ([]*client.ContractFnSig, error) {
	return ism.NewLuaExecutor(
		contractAddress,
		idx.ismState,
		idx.sqlState,
		definition,
		&ism.ExecutorContext{
			Sender:    "",
			BlockHash: "",
			Timestamp: time.Now(),
			Node:      idx.nodeID,
		},
	).FnSigs(dbTx)
}

func (idx *ISMIndex) verifySignature(addr, sign, data string) error {
	// get Signature
	signature, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return fmt.Errorf("fail to verify: %v", err)
	}

	// get expected data
	var expDataBuf bytes.Buffer
	wire.WriteVarString(&expDataBuf, 0, "Bitcoin Signed Message:\n")
	wire.WriteVarString(&expDataBuf, 0, data)
	expDataHash := wire.DoubleSha256(expDataBuf.Bytes())

	// reconstruct the public key hash
	pubkey, wasComp, err := btcec.RecoverCompact(btcec.S256(),
		signature,
		expDataHash)
	var serializedPubKey []byte
	if wasComp {
		serializedPubKey = pubkey.SerializeCompressed()
	} else {
		serializedPubKey = pubkey.SerializeUncompressed()
	}
	derivedAddr, err := btcutil.NewAddressPubKey(serializedPubKey, idx.chainParams)
	if err != nil {
		return fmt.Errorf("fail to verify: %v", err)
	}

	// verify address
	if derivedAddr.EncodeAddress() != addr {
		return fmt.Errorf("fail to verify: signature is not proper")
	}

	return nil
}

type SignedQuery struct {
	Signed *bool            `json:"signed"`
	Sender string           `json:"sender"`
	Sign   string           `json:"sign"`
	Body   *json.RawMessage `json:"body"`
}

func (idx *ISMIndex) QueryContract(dbTx database.Tx, contractAddress string, query *json.RawMessage) (*ISMQueryResult, error) {
	if idx.EphemeralEnabled {
		idx.lock.RLock()
		defer idx.lock.RUnlock()
	}

	queryStartTime := time.Now()
	defer func() {
		idx.ismState.Stat.Query.Total.AddDelta(queryStartTime)
		idx.ismState.Stat.Query.Count++
	}()
	bquery := []byte(*query)
	strQuery := string(bquery)
	log.Debug(strQuery)

	var queryBody []byte

	signedQuery := &SignedQuery{}
	err := json.Unmarshal(bquery, signedQuery)
	if err != nil {
		log.Debug("old query doesn't have a signature")
		log.Debugf("Query Contract ", query)
		queryBody = []byte(*query)
	} else if signedQuery.Signed != nil {
		log.Tracef("Query Contract is signed = %v", *signedQuery.Signed)
		log.Tracef("Query Contract sender = %v", signedQuery.Sender)
		log.Tracef("Query Contract body = %s", *signedQuery.Body)

		queryBody = []byte(*signedQuery.Body)

		// verify a signature
		if *signedQuery.Signed {
			err := idx.verifySignature(
				signedQuery.Sender,
				signedQuery.Sign,
				string(*signedQuery.Body))
			if err != nil {
				return nil, err
			}
		}
	} else {
		log.Debug("query is not signed")
		log.Debugf("Query Contract ", query)
		queryBody = bquery
	}

	if queryBody == nil {
		log.Infof("nil contract query")
		return nil, errors.New("query is empty")
	}

	instance := idx.ismState.GetInstance(dbTx, []byte(contractAddress))
	if instance == nil {
		errStr := fmt.Sprintf("contract instance(%v) not found", contractAddress)
		log.Trace(errStr)
		return nil, errors.New(errStr)
	}

	// parse query
	definition := instance.Get([]byte(contractBodyKey))
	if definition == nil {
		return nil, fmt.Errorf("contract instance(%v) not found", contractAddress)
	}

	body := opencontracts.Body{}
	err = opencontracts.ParsePayloadBody(queryBody, &body)
	if nil != err {
		return nil, err
	}
	err = idx.construeContractBody(&body)
	if nil != err {
		return nil, err
	}

	if body.Type == "LSC" {
		return idx.queryLua(dbTx, contractAddress, definition, signedQuery, body)
	} else if body.Type == "ESC" {
		return idx.queryETH(dbTx, contractAddress, body)
	} else {
		log.Tracef("Invalid contract type")
		return nil, errQuery
	}
}

func (idx *ISMIndex) queryETH(dbTx database.Tx, contractAddress string, body opencontracts.Body) (*ISMQueryResult, error) {
	return nil, nil
}

func (idx *ISMIndex) queryLua(dbTx database.Tx, contractAddress string, definition []byte, signedQuery *SignedQuery, body opencontracts.Body) (*ISMQueryResult, error) {
	executor := ism.NewLuaExecutor(
		[]byte(contractAddress),
		idx.ismState,
		idx.sqlState,
		definition,
		&ism.ExecutorContext{
			Sender:    signedQuery.Sender,
			BlockHash: "",
			Timestamp: time.Now(),
			Node:      idx.nodeID,
		},
	)
	if executor == nil {
		return nil, errors.New("failed to create the query executor")
	}

	result, err := executor.Query(dbTx, body.Body)
	if nil != err {
		luaError, ok := err.(*ism.LuaError)
		if !ok {
			return nil, errQuery
		}

		// create error result
		encodedError, err := json.Marshal(luaError)
		if nil != err {
			log.Tracef("failed to marshal error - %v", err)
			return nil, errQuery
		}

		jsonError := json.RawMessage(encodedError)
		resultContainer := &ISMQueryResult{
			Success: false,
			Result:  nil,
			Error:   &jsonError,
		}

		return resultContainer, nil
	}

	jsonResult := json.RawMessage(result)
	resultContainer := &ISMQueryResult{
		Success: true,
		Result:  &jsonResult,
		Error:   nil,
	}

	log.Trace("query lock finished")
	return resultContainer, nil
}

func (idx *ISMIndex) SetNodeGroupKey(key string) {
	idx.nodeGroupWIF, _ = btcutil.DecodeWIF(key)
}

func (idx *ISMIndex) SetNodeID(nodeid string) {
	log.Tracef("Set NodeID %s", nodeid)
	idx.nodeID = nodeid
}

func (idx *ISMIndex) GetNodeGroupPubKeyBytes() []byte {
	if idx.nodeGroupWIF != nil {
		return idx.nodeGroupWIF.PrivKey.PubKey().SerializeCompressed()
	}
	return nil
}

func (idx *ISMIndex) SetInstanceEncryptKey(key string) {
	idx.ismState.SetInstanceEncryptKey([]byte(key))
}

func (idx *ISMIndex) DisableLStateCache() {
	idx.disabledLStateCache = true
}

func (idx *ISMIndex) AddUnconfirmedTx(tx *btcutil.Tx, view *blockchain.UtxoViewpoint, bestState *blockchain.BestState) {
	if idx.EphemeralEnabled {
		idx.lock.Lock()
		defer idx.lock.Unlock()
	}

	blockInfo := &blockInformation{
		BlockHeight:    bestState.Height,
		BlockHash:      bestState.Hash.String(),
		BlockTimestamp: time.Now(),
		Confirmed:      false,
	}
	_ = idx.db.View(func(dbTx database.Tx) error {
		idx.processTx(dbTx, blockInfo, tx, view)
		return nil
	})
}
func (idx *ISMIndex) EnableEphemeral() {
	idx.EphemeralEnabled = true
	idx.ismState.EphemeralEnabled = true
}

func (idx *ISMIndex) EnablePurgeOldUndoStage() {
	idx.PurgeOldUndoStage = true
}
