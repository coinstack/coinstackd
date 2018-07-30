// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2013-2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"

	"bytes"

	"github.com/coinstack/coinstackd/chaincfg"
	"github.com/coinstack/coinstackd/chainmaker"
	"github.com/coinstack/btcutil"
	"github.com/coinstack/btcutil/base58"
	flags "github.com/btcsuite/go-flags"
)

type config struct {
	SigningKey string `short:"k" long:"key" description:"Private key to create genesis block with"`
	Flag       string `short:"f" long:"flag" description:"Coinbase flag to create genesis block with"`
}

func main() {
	cfg := config{
		Flag: "/P2SH/btcd/",
	}
	parser := flags.NewParser(&cfg, flags.Default)
	_, err := parser.Parse()
	if err != nil {
		if e, ok := err.(*flags.Error); !ok || e.Type != flags.ErrHelp {
			parser.WriteHelp(os.Stderr)
		}
		return
	}

	if cfg.SigningKey == "" {
		fmt.Fprintf(os.Stderr, "Private key missing\n")
		os.Exit(1)
	}

	// get correct difficulty value with num leading zeroes
	nodeKey, _ := btcutil.DecodeWIF(cfg.SigningKey)
	if cfg.SigningKey == "" {
		fmt.Fprintf(os.Stderr, "Failed to parse key\n")
		os.Exit(1)
	}
	toAddress, _ := btcutil.NewAddressPubKey(nodeKey.SerializePubKey(), &chaincfg.MainNetParams)
	if cfg.SigningKey == "" {
		fmt.Fprintf(os.Stderr, "Failed to derive address\n")
		os.Exit(1)
	}
	block, _ := chainmaker.CreateGenesisBlock(cfg.Flag, 2, toAddress)
	var buf bytes.Buffer
	block.Serialize(&buf)

	base58Encoded := base58.Encode(buf.Bytes())
	chainIDString := chainmaker.CalculateChainID(block)

	fmt.Printf("[Chain ID]\n%v\n", chainIDString)
	fmt.Printf("[Admin Address]\n%v\n", toAddress)
	fmt.Printf("[Genesis Block Hash]\n%v\n", block.BlockSha().String())
	fmt.Printf("[Serialized Genesis Block]\n%v\n", base58Encoded)

}
