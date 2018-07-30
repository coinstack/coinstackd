// Copyright (c) 2016 BLOCKO INC.
// Package coinstack comes from github.com/coinstack/coinstack-core
// And this websocket_processor.go file comes from core/websocket_processor.go
// of coinstack-core
package main

import (
	"encoding/json"

	client "github.com/coinstack/coinstackd/coinstack/client"
	"github.com/coinstack/coinstackd/coinstack/sync"
)

// nolint: golint
const (
	CMD_FETCH_BLOCKCHAIN_STATUS = 1 + iota
	CMD_FETCH_BLOCK_TRANSACTIONS
	CMD_FETCH_BLOCK
	CMD_FETCH_TRANSACTION
	CMD_FETCH_TRANSACTION_HISTORY
	CMD_FETCH_BALANCE
	CMD_FETCH_UNSPENTOUTPUTS
	CMD_PUSH_TRANSACTION
	CMD_FETCH_CONTRACT_STATUS
	CMD_QUERY_CONTRACT
)

type WebsocketInput struct {
	ThreadID  int64  `json:"ti"`
	Cmd       int    `json:"cmd"`
	Blockhash string `json:"blockhash"`
	Txhash    string `json:"txhash"`
	Address   string `json:"address"`
	RawTx     string `json:"rawtx"`
	Query     struct {
		CodeType string           `json:"type"`
		Body     *json.RawMessage `json:"body"`
	} `json:"query"`
}

type WebsocketOutput struct {
	ThreadID int64       `json:"ti"`
	Status   int         `json:"st"`
	Result   interface{} `json:"result"`
}

func GenerateError(threadID int64, status int, cause string) WebsocketOutput {
	coinstackErr := client.NewCoinStackError(status).SetCause(cause)

	return WebsocketOutput{ThreadID: threadID,
		Status: coinstackErr.Status(), Result: coinstackErr}
}

func ProcessWebsocket(db *CoinstackAdaptor, input WebsocketInput) interface{} {

	switch input.Cmd {
	case CMD_FETCH_BLOCKCHAIN_STATUS:
		status, err := db.FetchBlockchainStatus()
		if nil != err {
			return GenerateError(input.ThreadID, client.InternalServer, err.Error())
		}

		return WebsocketOutput{ThreadID: input.ThreadID, Status: 200, Result: status}

	case CMD_FETCH_BLOCK_TRANSACTIONS:
		if len(input.Blockhash) == 0 {
			return GenerateError(input.ThreadID, client.ValidationFailed,
				"a blockhash field is empty")
		}
		txs, err := db.FetchBlockTransactions(input.Blockhash)
		if nil != err {
			return GenerateError(input.ThreadID, client.InternalServer, err.Error())
		}

		return WebsocketOutput{ThreadID: input.ThreadID, Status: 200, Result: txs}

	case CMD_FETCH_BLOCK:
		if len(input.Blockhash) == 0 {
			return GenerateError(input.ThreadID, client.ValidationFailed,
				"a blockhash field is empty")
		}
		block, ok, err := db.FetchBlock(input.Blockhash, "")
		if nil != err {
			return GenerateError(input.ThreadID, client.InternalServer, err.Error())
		}
		if !ok {
			return GenerateError(input.ThreadID, client.ResourceNotFound, "Requested block not found.")
		}

		return WebsocketOutput{ThreadID: input.ThreadID, Status: 200, Result: block}

	case CMD_FETCH_TRANSACTION:
		if len(input.Txhash) == 0 {
			return GenerateError(input.ThreadID, client.ValidationFailed,
				"a txhash field is empty")
		}
		tx, ok, err := db.FetchTransaction(input.Txhash, "")
		if nil != err {
			return GenerateError(input.ThreadID, client.InternalServer, err.Error())
		}
		if !ok {
			return GenerateError(input.ThreadID, client.ResourceNotFound, "Requested transaction not found.")
		}

		return WebsocketOutput{ThreadID: input.ThreadID, Status: 200, Result: tx}

	case CMD_FETCH_TRANSACTION_HISTORY:
		//TODO apply pagination logic
		if len(input.Address) == 0 {
			return GenerateError(input.ThreadID, client.ValidationFailed,
				"a address field is empty")
		}
		txs, err := db.FetchTransactionHistory(input.Address)
		if nil != err {
			return GenerateError(input.ThreadID, client.InternalServer, err.Error())
		}

		return WebsocketOutput{ThreadID: input.ThreadID, Status: 200, Result: txs}

	case CMD_FETCH_BALANCE:
		if len(input.Address) == 0 {
			return GenerateError(input.ThreadID, client.ValidationFailed,
				"a address field is empty")
		}
		balance, err := db.FetchBalance(input.Address)
		if nil != err {
			return GenerateError(input.ThreadID, client.InternalServer, err.Error())
		}

		return WebsocketOutput{ThreadID: input.ThreadID, Status: 200,
			Result: map[string]interface{}{"balance": balance}}

	case CMD_FETCH_UNSPENTOUTPUTS:
		if len(input.Address) == 0 {
			return GenerateError(input.ThreadID, client.ValidationFailed,
				"a address field is empty")
		}
		//TODO apply amount logic
		uxtos, err := db.FetchUnspentOutputs(input.Address, 0)
		if nil != err {
			return GenerateError(input.ThreadID, client.InternalServer, err.Error())
		}

		return WebsocketOutput{ThreadID: input.ThreadID, Status: 200, Result: uxtos}

	case CMD_PUSH_TRANSACTION:
		if db.SupportsTxBroadcast() {
			if len(input.RawTx) == 0 {
				return GenerateError(input.ThreadID, client.ValidationFailed,
					"a rawtx field is empty")
			}
			err := db.PushTransaction(input.RawTx)
			if nil != err {
				switch err := err.(type) {
				case sync.IllegalTxError:
					return GenerateError(input.ThreadID, client.ValidationFailed, err.Cause)
				case sync.DuplicateTxError:
					return GenerateError(input.ThreadID, client.ValidationFailed, "Transaction already submitted")
				default:
					restLog.Criticalf("Internal server error: %v", err)
					return GenerateError(input.ThreadID, client.InternalServer, err.Error())
				}
			}

			return WebsocketOutput{ThreadID: input.ThreadID, Status: 200,
				Result: map[string]interface{}{"status": "successful"}}
		}
		// websocket client does not support reverse proxy
		return GenerateError(input.ThreadID, client.InternalServer,
			"pushing a tx using an websocket client is not supported")

		// smart contract API
	case CMD_FETCH_CONTRACT_STATUS:
		if len(input.Address) == 0 {
			return GenerateError(input.ThreadID, client.ValidationFailed,
				"a address field is empty")
		}
		contractStatus, ok, err := db.FetchContractStatus(input.Address)
		if nil != err {
			return GenerateError(input.ThreadID, client.InternalServer,
				"Failed to fetch contract.")
		}
		if !ok {
			return GenerateError(input.ThreadID, client.ResourceNotFound,
				"Requested contract not found.")
		}

		return WebsocketOutput{ThreadID: input.ThreadID, Status: 200,
			Result: contractStatus}

	case CMD_QUERY_CONTRACT:
		if len(input.Address) == 0 {
			return GenerateError(input.ThreadID, client.ValidationFailed,
				"a address field is empty")
		} else if input.Query.Body == nil {
			return GenerateError(input.ThreadID, client.ValidationFailed,
				"a query field is empty")
		}

		contractResult, ok, err := db.QueryContract(input.Address, input.Query.Body)
		if nil != err {
			restLog.Errorf("Internal server error: %v", err)
			return GenerateError(input.ThreadID, client.InternalServer,
				err.Error())
		}
		if !ok {
			return GenerateError(input.ThreadID, client.ResourceNotFound,
				"Requested contract not found.")
		}

		return WebsocketOutput{ThreadID: input.ThreadID, Status: 200,
			Result: contractResult}
	}

	return GenerateError(input.ThreadID, client.InternalServer, "unsupported type of cmd")
}
