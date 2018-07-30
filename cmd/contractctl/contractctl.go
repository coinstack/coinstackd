// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/coinstack/coinstackd/blockchain/indexers/ism"
	"github.com/coinstack/coinstackd/blockchain/indexers/ism/sql"
	"github.com/coinstack/coinstackd/database"
	_ "github.com/coinstack/coinstackd/database/ffldb"
	"github.com/coinstack/coinstackd/wire"
	"github.com/btcsuite/btclog"
	flags "github.com/btcsuite/go-flags"
	"github.com/btcsuite/seelog"
)

const (
	ismDbType       = "ffldb"
	ismBlockDataNet = wire.MainNet
)

var (
	currentBlock int32 = 10000
	currentTx    int32 = 20000
)

type config struct {
	DefinitionFile     string   `short:"d" long:"definition" description:"Contract definition file"`
	Type               string   `short:"t" long:"type" description:"Smart contract type {lsc, esc}"`
	ContractDefAddress string   `short:"a" long:"address" description:"Smart contract address - defaults to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"`
	Executions         []string `short:"e" long:"exec" description:"Invocation file"`
	Verbose            bool     `short:"v" long:"verbose" description:"Verbose mode"`
}

func fileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func nextBlock() {
	currentBlock++
}

func getCurrentBlockHash() string {
	return hex.EncodeToString(wire.DoubleSha256([]byte(fmt.Sprintf("%v", currentBlock))))
}

func getCurrentBlockHeight() int32 {
	return currentBlock
}

func nextTx() {
	currentTx++
}

func getCurrentTxHash() string {
	return hex.EncodeToString(wire.DoubleSha256([]byte(fmt.Sprintf("%v", currentTx))))
}

func main() {
	cfg := config{
		Type:               "lsc",
		ContractDefAddress: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
	}
	parser := flags.NewParser(&cfg, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			parser.WriteHelp(os.Stderr)
		}
		return
	}

	if cfg.Type != "lsc" && cfg.Type != "esc" {
		fmt.Fprintf(os.Stderr, "Unrecongnized contract type\n")
		os.Exit(1)
	}

	if !fileExists(cfg.DefinitionFile) {
		fmt.Fprintf(os.Stderr, "Failed to open file %v: %v\n", cfg.DefinitionFile, err)
		os.Exit(1)
	}

	definition, err := ioutil.ReadFile(cfg.DefinitionFile)
	if nil != err {
		fmt.Fprintf(os.Stderr, "Failed to open file %v: %v\n", cfg.DefinitionFile, err)
		os.Exit(1)
	}

	if cfg.Verbose {
		c := `
	<seelog>
		<outputs formatid="all">
			<console/>
		</outputs>
		<formats>
			<format id="all" format="%Time [%LEV] %Msg%n" />
		</formats>
	</seelog>`
		consoleLogger, err := seelog.LoggerFromConfigAsString(c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create logger: %v", err)
			os.Exit(1)
		}
		logger := btclog.NewSubsystemLogger(consoleLogger, "")
		logger.SetLevel(btclog.TraceLvl)
		ism.UseLogger(logger)
		defer logger.Close()
	}

	// create executor
	// create test context
	dbPath := filepath.Join(os.TempDir(), "test-ismindex")
	_ = os.RemoveAll(dbPath)
	idb, err := database.Create(ismDbType, dbPath, ismBlockDataNet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create database (%s) %v\n", ismDbType, err)
		os.Exit(1)
	}
	defer os.RemoveAll(dbPath)
	defer idb.Close()

	ism.ReplaceDebugPrint()

	ismState := ism.NewState()
	err = sql.LoadDatabase(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create database (%s) %v\n", "sqldb", err)
		os.Exit(1)
	}
	defer sql.Close()
	sqlState := ism.NewSQLState(ismState)

	err = idb.Update(func(tx database.Tx) error {
		ismState.Create(tx)
		sqlState.Init(tx)

		ismState.NewStage(tx, []byte(getCurrentBlockHash()))
		sqlState.NewStage(tx)
		ismState.CreateInstance(tx, []byte(cfg.ContractDefAddress))

		context := ism.ExecutorContext{
			Sender:      cfg.ContractDefAddress, // caller
			BlockHash:   getCurrentBlockHash(),
			BlockHeight: getCurrentBlockHeight(),
			TxHash:      getCurrentTxHash(),
			Timestamp:   time.Now(),
		}
		executor := ism.NewLuaExecutor(
			[]byte(cfg.ContractDefAddress),
			ismState,
			sqlState,
			definition,
			&context)
		executor.Debug = true
		executor.NextBlockHook = func() {
			ismState.Commit(tx, []byte(cfg.ContractDefAddress))
			nextBlock()
			fmt.Printf("\x1b[32m")
			fmt.Printf("==> \x1b[0m")
			fmt.Printf("Processing block \x1b[33m[%v] \x1b[32m[%v]\n", getCurrentBlockHeight(), getCurrentBlockHash()[0:5])
			fmt.Printf("\x1b[0m")
			err = ismState.NewStage(tx, []byte(getCurrentBlockHash()))
			if nil != err {
				fmt.Fprintf(os.Stderr, "Failed to process execution at block %v\n", getCurrentBlockHeight())
				os.Exit(1)
			}
			context.Confirmed = true
			context.BlockHash = getCurrentBlockHash()
			context.BlockHeight = getCurrentBlockHeight()
			sqlState.NewStage(tx)
		}

		executor.NextTxHook = func() {
			nextTx()
			context.TxHash = getCurrentTxHash()
		}

		executor.MempoolHook = func() {
			ismState.Commit(tx, []byte(cfg.ContractDefAddress))
			fmt.Printf("\x1b[32m")
			fmt.Printf("==> \x1b[0m")
			fmt.Printf("Entering unconfirmed state\n")
			fmt.Printf("\x1b[0m")
			context.Confirmed = false

		}

		err := executor.Init(tx)
		if nil != err {
			fmt.Fprintf(os.Stderr, "Failed to initialize executor - %v", err)
			os.Exit(1)
		}

		for _, execFile := range cfg.Executions {
			if !fileExists(execFile) {
				fmt.Fprintf(os.Stderr, "Failed to open file %v: %v\n", execFile, err)
				os.Exit(1)
			}

			executionString, err := ioutil.ReadFile(execFile)
			if nil != err {
				fmt.Fprintf(os.Stderr, "Failed to open file %v: %v\n", executionString, err)
				os.Exit(1)
			}

			executor.NextBlockHook()
			executor.NextTxHook()
			err = executor.Execute(tx, []byte(executionString))
			if nil != err {
				fmt.Fprintf(os.Stderr, "Failed to execute file %v: %v\n", execFile, err)
				os.Exit(1)
			}
		}

		return nil
	})

}
