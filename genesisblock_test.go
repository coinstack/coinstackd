// Copyright (c) 2016 BLOCKO INC.
package main

import (
	"bytes"
	"github.com/coinstack/coinstackd/chaincfg"
	"github.com/coinstack/coinstackd/chainmaker"
	"github.com/coinstack/coinstackd/wire"
	"github.com/coinstack/btcutil"
	"github.com/coinstack/btcutil/base58"
	"testing"
)

func TestTemp(t *testing.T) {
	// get correct difficulty value with num leading zeroes
	toAddress, _ := btcutil.DecodeAddress("19pta6x1hXzV9F5hHnhMARYbRjuxF6xbbV", &chaincfg.MainNetParams)
	block, _ := chainmaker.CreateGenesisBlock("/P2SH/btcd/", 2, toAddress)
	t.Log(block.Header)
	var buf bytes.Buffer
	block.Serialize(&buf)

	base58Encoded := base58.Encode(buf.Bytes())
	t.Log(base58Encoded)

	reader := bytes.NewReader(base58.Decode(base58Encoded))
	var block2 wire.MsgBlock
	block2.Deserialize(reader)
	t.Log(block2.Header)

	chainIDString := chainmaker.CalculateChainID(&block2)
	t.Logf("%v", chainIDString)

}
