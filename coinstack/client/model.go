// Copyright (c) 2016 BLOCKO INC.
// Package client comes from github.com/coinstack/coinstack-client
// And this model.go file comes from model.go of coinstack-client
package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"bytes"

	"strings"

	"github.com/vrischmann/jsonutil"
	"gopkg.in/mgo.v2/bson"
)

// nolint: golint
const (
	BlockMessage = iota
	TxMessage
	PingMessage
	PongMessage
)

type BlockchainStatus struct {
	BestBlockHash string `bson:"blockHash" json:"best_block_hash"`
	BestHeight    int32  `bson:"blockHeight" json:"best_height"`
}

type Work big.Int

type Block struct {
	Hash           string    `bson:"_id" json:"block_hash"`
	Height         int32     `bson:"height" json:"height"`
	Time           time.Time `json:"confirmation_time"`
	Parent         string    `bson:"parent" json:"parent,omitempty"`
	Children       []string  `bson:"children" json:"children,omitempty"`
	Transactions   []string  `json:"transaction_list"`
	Work           *Work     `json:"-"`
	CumulativeWork *Work     `json:"-"`
	Processed      bool      `json:"-"`
	Bestchain      bool      `json:"-"`
}

func (work *Work) GetBSON() (interface{}, error) {
	if nil == work {
		return "", nil
	}
	intWork := (*big.Int)(work)
	return intWork.String(), nil
}

func (work *Work) SetBSON(raw bson.Raw) error {
	var workString string
	err := raw.Unmarshal(&workString)
	if nil != err {
		fmt.Println("unmarshal not ok")
		return errors.New("failed to unmarshal work")
	}
	if workString == "" {
		*work = Work(*big.NewInt(0))
	} else {
		intWork, ok := big.NewInt(0).SetString(workString, 10)
		if !ok {
			return errors.New("failed to unmarshal work")
		}
		*work = Work(*intWork)
	}
	return nil
}

func (work *Work) String() string {
	return (*big.Int)(work).String()
}

func (work *Work) Cmp(y *Work) int {
	return (*big.Int)(work).Cmp((*big.Int)(y))
}

func (work *Work) Add(x *Work, y *Work) *Work {
	addedInt := (*big.Int)(work).Add((*big.Int)(x), (*big.Int)(y))
	addedWork := (*Work)(addedInt)
	return addedWork
}

func NewWork(amount int64) *Work {
	work := Work(*big.NewInt(amount))
	return &work
}

type BlockHash struct {
	Hash      string `bson:"blockhash" json:"block_hash"`
	Height    int32  `bson:"blockheight" json:"block_height"`
	BestChain bool   `bson:"bestchain" json:"-"`
}

type Input struct {
	TransactionHash string    `bson:"hash" json:"transaction_hash"`
	OutputIndex     int32     `bson:"vout" json:"output_index"`
	Address         []string  `bson:"address" json:"address"`
	Value           string    `bson:"value" json:"value"`
	Script          string    `bson:"-" json:"-"`
	Metadata        *Metadata `bson:"-" json:"-"`
}

type OpenAssetsVersion struct {
	MajorVersion uint16 `bson:"major_version" json:"major_version"`
	MinorVersion uint16 `bson:"minor_version" json:"minor_version"`
}

type OpenAssetsMeta struct {
	OutputType string             `bson:"output_type" json:"output_type"`
	Version    *OpenAssetsVersion `bson:"version,omitempty" json:"version,omitempty"`
	AssetID    string             `bson:"asset_id,omitempty" json:"asset_id,omitempty"`
	Quantity   uint64             `bson:"quantity" json:"quantity"`
}

type Metadata struct {
	OpenAssets *OpenAssetsMeta `json:"openassets,omitempty"`
}

type Output struct {
	Index    int32     `bson:"index" json:"index"`
	Address  []string  `bson:"address" json:"address,omitempty"`
	Value    string    `bson:"value" json:"value,omitempty"`
	Script   string    `bson:"script" json:"script"`
	Spent    bool      `bson:"used" json:"used"`
	Metadata *Metadata `bson:"metadata,omitempty" json:"metadata,omitempty"`
}

type UnspentOutput struct {
	TransactionHash string    `json:"transaction_hash"`
	Index           int32     `json:"index"`
	Value           string    `json:"value,omitempty"`
	Script          string    `json:"script"`
	Confirmations   int32     `json:"confirmations"`
	Metadata        *Metadata `json:"metadata,omitempty"`
}

type Transaction struct {
	Hash          string      `bson:"_id" json:"transaction_hash"`
	Blocks        []BlockHash `bson:"blockhash" json:"block_hash"`
	Coinbase      bool        `bson:"coinbase" json:"coinbase"`
	IsDeleted     bool        `bson:"is_deleted" json:"is_deleted"`
	Inputs        []Input     `json:"inputs"`
	Outputs       []Output    `json:"outputs"`
	Time          *time.Time  `bson:"timestamp" json:"time"`
	BroadcastTime *time.Time  `bson:"initialtimestamp,omitempty" json:"broadcast_time,omitempty"`
	Addresses     []string    `json:"addresses"`
}

type WebSocketPayload struct {
	Type    int
	Payload *json.RawMessage
}

type BlockEvent func(block *Block)
type TxEvent func(block *Transaction)

type PushTxRequest struct {
	Tx string
}

type ContractStatus struct {
	ContractID   []string `bson:"contract_id" json:"contract_id"`
	Terminated   bool     `bson:"terminated" json:"terminated"`
	ContractHash string   `bson:"contract_hash,omitempty" json:"contract_hash,omitempty"`
	ContractType string   `bson:"contract_type,omitempty" json:"contract_type,omitempty"`
}

type ContractQuery struct {
	Query *json.RawMessage
}

type Publickey struct {
	Publickey []byte `json:"pubkey"`
}

type Permission struct {
	Permission byte `json:"permission"`
}

type ContractGrantee struct {
	Address string `json:"address"`
	Token   string `json:"token"`
}

type ContractFnArgs []string

type ContractFnSig struct {
	Name     string         `json:"name"`
	Args     ContractFnArgs `json:"args"`
	Variadic bool           `json:"variadic"`
	SrcPos   int            `json:"-"`
}

func (fnSig *ContractFnSig) String() string {
	if fnSig == nil {
		return ""
	}
	var buffer bytes.Buffer
	buffer.WriteString("name:")
	buffer.WriteString(fnSig.Name)
	buffer.WriteString(",args:[")
	args := make([]string, len(fnSig.Args))
	for i, v := range fnSig.Args {
		args[i] = string(v)
	}
	buffer.WriteString(strings.Join(args, ","))
	buffer.WriteString("],variadic:")
	if fnSig.Variadic {
		buffer.WriteString("true")
	} else {
		buffer.WriteString("false")
	}
	return buffer.String()
}

type ContractFnSigs []*ContractFnSig

func (fnSigs ContractFnSigs) String() string {
	buffer := make([]string, len(fnSigs))
	for i, v := range fnSigs {
		buffer[i] = v.String()
	}
	return strings.Join(buffer, "\n")
}

type Duration struct {
	jsonutil.Duration
}

func (d *Duration) AddDelta(startTime time.Time) {
	d.Duration.Duration += time.Now().Sub(startTime)
}

type ContractExStat struct {
	Total   Duration `json:"total_time"`
	Prepare Duration `json:"prepare_time,omitempty"`
	Init    Duration `json:"init_time,omitempty"`
	Run     Duration `json:"run_time,omitempty"`
	Commit  Duration `json:"commit_time,omitempty"`
	Count   int      `json:"count"`
}

type ContractStat struct {
	Connect           Duration       `json:"total_time"`
	ContractIDExtract Duration       `json:"contractid_extract_time"`
	ParseMarkerOutput Duration       `json:"parse_marker_output_time"`
	ConstrueContract  Duration       `json:"construe_contract_time"`
	SenderExtract     Duration       `json:"sender_extract_time"`
	Def               ContractExStat `json:"def_stat"`
	Exec              ContractExStat `json:"exec_stat"`
	Query             ContractExStat `json:"query_stat"`
}
