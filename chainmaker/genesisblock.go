// Copyright (c) 2016 BLOCKO INC.
package chainmaker

import (
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/coinstack/coinstackd/blockchain"
	"github.com/coinstack/coinstackd/chaincfg"
	"github.com/coinstack/coinstackd/txscript"
	"github.com/coinstack/coinstackd/wire"
	"github.com/coinstack/btcutil"
	"github.com/coinstack/btcutil/base58"
)

const (
	generatedBlockVersion = 4

	// mining
	// maxNonce is the maximum value a nonce can be in a block header.
	maxNonce = ^uint32(0) // 2^32 - 1

	// maxExtraNonce is the maximum value an extra nonce used in a coinbase
	// transaction can be.
	maxExtraNonce = ^uint64(0) // 2^64 - 1

	// BEP-001 chain ID version bytes
	chainIDversion = byte(28)
)

func updateExtraNonce(flags string, msgBlock *wire.MsgBlock, blockHeight int32, extraNonce uint64) error {
	coinbaseScript, err := standardCoinbaseScript(flags, blockHeight, extraNonce)
	if err != nil {
		return err
	}
	if len(coinbaseScript) > blockchain.MaxCoinbaseScriptLen {
		return fmt.Errorf("coinbase transaction script length "+
			"of %d is out of range (min: %d, max: %d)",
			len(coinbaseScript), blockchain.MinCoinbaseScriptLen,
			blockchain.MaxCoinbaseScriptLen)
	}
	msgBlock.Transactions[0].TxIn[0].SignatureScript = coinbaseScript

	// TODO(davec): A btcutil.Block should use saved in the state to avoid
	// recalculating all of the other transaction hashes.
	// block.Transactions[0].InvalidateCache()

	// Recalculate the merkle root with the updated extra nonce.
	block := btcutil.NewBlock(msgBlock)
	merkles := blockchain.BuildMerkleTreeStore(block.Transactions())
	msgBlock.Header.MerkleRoot = *merkles[len(merkles)-1]
	return nil
}

func solveBlock(flags string, msgBlock *wire.MsgBlock, blockHeight int32) bool {
	ticker := time.NewTicker(time.Second * 10)

	// Choose a random extra nonce offset for this block template and
	// worker.
	enOffset, err := wire.RandomUint64()
	if err != nil {
		enOffset = 0
	}

	// Create a couple of convenience variables.
	header := &msgBlock.Header
	targetDifficulty := blockchain.CompactToBig(header.Bits)

	// Initial state.
	hashesCompleted := uint64(0)

	// Note that the entire extra nonce range is iterated and the offset is
	// added relying on the fact that overflow will wrap around 0 as
	// provided by the Go spec.
	for extraNonce := uint64(0); extraNonce < maxExtraNonce; extraNonce++ {
		// Update the extra nonce in the block template with the
		// new value by regenerating the coinbase script and
		// setting the merkle root to the new value.  The
		updateExtraNonce(flags, msgBlock, blockHeight, extraNonce+enOffset)

		// Search through the entire nonce range for a solution while
		// periodically checking for early quit and stale block
		// conditions along with updates to the speed monitor.
		for i := uint32(0); i <= maxNonce; i++ {
			select {
			case <-ticker.C:
				hashRate := hashesCompleted / 10
				fmt.Printf("[hahrate] : %v per sec\n", hashRate)

				hashesCompleted = 0

			default:
				// Non-blocking select to fall through
			}

			// Update the nonce and hash the block header.  Each
			// hash is actually a double sha256 (two hashes), so
			// increment the number of hashes completed for each
			// attempt accordingly.
			header.Nonce = i
			hash := header.BlockSha()
			hashesCompleted += 2

			// The block is solved when the new block hash is less
			// than the target difficulty.  Yay!
			if blockchain.ShaHashToBig(&hash).Cmp(targetDifficulty) <= 0 {
				return true
			}
		}
	}

	return false
}

func standardCoinbaseScript(flag string, nextBlockHeight int32, extraNonce uint64) ([]byte, error) {
	return txscript.NewScriptBuilder().AddInt64(int64(nextBlockHeight)).
		AddInt64(int64(extraNonce)).AddData([]byte(flag)).
		Script()
}

func createCoinbaseTx(coinbaseScript []byte, nextBlockHeight int32, addr btcutil.Address, defaultNet *chaincfg.Params) (*btcutil.Tx, error) {
	// Create the script to pay to the provided payment address if one was
	// specified.  Otherwise create a script that allows the coinbase to be
	// redeemable by anyone.
	var pkScript []byte
	if addr != nil {
		var err error
		pkScript, err = txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		scriptBuilder := txscript.NewScriptBuilder()
		pkScript, err = scriptBuilder.AddOp(txscript.OP_TRUE).Script()
		if err != nil {
			return nil, err
		}
	}

	tx := wire.NewMsgTx()
	tx.AddTxIn(&wire.TxIn{
		// Coinbase transactions have no inputs, so previous outpoint is
		// zero hash and max index.
		PreviousOutPoint: *wire.NewOutPoint(&wire.ShaHash{},
			wire.MaxPrevOutIndex),
		SignatureScript: coinbaseScript,
		Sequence:        wire.MaxTxInSequenceNum,
	})
	tx.AddTxOut(&wire.TxOut{
		Value: blockchain.CalcBlockSubsidy(nextBlockHeight,
			defaultNet),
		PkScript: pkScript,
	})
	return btcutil.NewTx(tx), nil
}

func calcDifficulty(numLeadingZeroes int) *big.Int {
	newDifficulty := blockchain.CompactToBig(0x1d00ffff)
	if numLeadingZeroes < 8 {
		zeroCount := 8 - numLeadingZeroes
		for i := 0; i < zeroCount; i++ {
			newDifficulty.Mul(newDifficulty, big.NewInt(0x10))
		}
	}
	if numLeadingZeroes > 8 {
		zeroCount := numLeadingZeroes - 8
		for i := 0; i < zeroCount; i++ {
			newDifficulty.Div(newDifficulty, big.NewInt(0x10))
		}
	}
	return newDifficulty
}

// CreateGenesisBlock creates a private net genesis block with given configuration
func CreateGenesisBlock(flags string, difficulty int, toAddress btcutil.Address) (*wire.MsgBlock, error) {

	// get correct difficulty value with num leading zeroes
	newDifficulty := calcDifficulty(difficulty)

	// create a genesis block template
	var msgBlock wire.MsgBlock
	// block header
	msgBlock.Header = wire.BlockHeader{
		Version:    generatedBlockVersion,
		PrevBlock:  wire.ShaHash{},
		MerkleRoot: wire.ShaHash{},
		Timestamp:  time.Now(),
		Bits:       blockchain.BigToCompact(newDifficulty),
	}

	// block body needs to be populated with coinbase tx
	// create coinbase tx
	extraNonce := uint64(0)
	coinbaseScript, _ := standardCoinbaseScript(flags, 0, extraNonce)
	coinbaseTx, _ := createCoinbaseTx(coinbaseScript, 0, toAddress, &chaincfg.PrivateNetParams)

	blockTxns := make([]*btcutil.Tx, int64(0), 1)
	blockTxns = append(blockTxns, coinbaseTx)
	for _, tx := range blockTxns {
		if err := msgBlock.AddTransaction(tx.MsgTx()); err != nil {
			return nil, err
		}
	}

	// merkle root needs to be calculated
	merkles := blockchain.BuildMerkleTreeStore(blockTxns)
	msgBlock.Header.MerkleRoot = *merkles[len(merkles)-1]

	// solve it
	// nonce needs to be calculated for merkel root
	solved := solveBlock(flags, &msgBlock, 0)
	if !solved {
		return nil, errors.New("failed to find nonce for the block")
	}
	return &msgBlock, nil
}

// CalculateChainID calculates chain ID from genesis block as base58 string
func CalculateChainID(genesisBlock *wire.MsgBlock) string {
	blockHash := genesisBlock.Header.BlockSha()
	blockHashBytes := blockHash.Bytes()
	chainID := btcutil.Hash160(blockHashBytes)
	chainIDString := base58.CheckEncode(chainID, chainIDversion)
	return chainIDString
}
