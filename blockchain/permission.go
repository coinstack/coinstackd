// Copyright (c) 2016 BLOCKO INC.
package blockchain

import (
	"fmt"

	"github.com/coinstack/coinstackd/btcec"
	"github.com/coinstack/coinstackd/chaincfg"
	"github.com/coinstack/coinstackd/coinstack/permission"
	"github.com/coinstack/coinstackd/database"
	"github.com/coinstack/coinstackd/txscript"
	"github.com/coinstack/coinstackd/wire"
	"github.com/coinstack/btcutil"
)

func CalculateBlockSignature(signingKey string, merkleRoot []byte) ([]byte, []byte, error) {
	// load key and sign ECDSA
	key, err := btcutil.DecodeWIF(signingKey)
	if nil != err {
		return nil, nil, err
	}
	signature, err := btcec.SignCompact(btcec.S256(), key.PrivKey, merkleRoot, true)
	if nil != err {
		return nil, nil, err
	}

	pubkeyHash := btcutil.Hash160(key.SerializePubKey())

	return signature, pubkeyHash, nil
}

func checkBlockSignature(address string, merkleRoot []byte, signature []byte, chain *chaincfg.Params) (bool, error) {
	// load key and sign ECDSA
	publicKey, valid, err := btcec.RecoverCompact(btcec.S256(), signature, merkleRoot)
	if nil != err {
		return false, err
	}

	if !valid {
		return false, nil
	}

	signatureAddress, _ := btcutil.NewAddressPubKey(publicKey.SerializeCompressed(), chain)
	if signatureAddress.EncodeAddress() != address {
		return false, nil
	}

	return true, nil
}

func (b *BlockChain) CheckBlockPermission(permissionManager permission.Manager,
	block *btcutil.Block) error {

	err := b.db.View(func(dbTx database.Tx) error {
		if !permissionManager.IsPermissionEnabled(dbTx, permission.MinerMarker) {
			log.Debug("Checking Mining Permission is Disabled")
			return nil
		}

		msgBlock := block.MsgBlock()
		// examine inputs
		coinbaseTx := msgBlock.Transactions[0]

		if len(coinbaseTx.TxOut) < 3 {
			str := "block is missing miner signature"
			return ruleError(ErrScriptValidation, str)
		}

		// check miner address
		minerAddressOutput := coinbaseTx.TxOut[1]
		minerScript, err := txscript.ParseScript(minerAddressOutput.PkScript)
		if err != nil {
			str := "block is missing miner address - failed to parse script"
			return ruleError(ErrScriptValidation, str)
		}
		minerAddress, err := btcutil.NewAddressPubKeyHash(minerScript[0].Data, b.chainParams)
		if err != nil {
			str := "block is missing miner address"
			return ruleError(ErrScriptValidation, str)
		}

		// check merkle tree
		tempTx := coinbaseTx.Copy()
		tempTx.TxOut = []*wire.TxOut{tempTx.TxOut[0]}

		txCopyList := make([]*btcutil.Tx, len(msgBlock.Transactions))
		for i, tx := range msgBlock.Transactions {
			txCopyList[i] = btcutil.NewTx(tx)
		}
		txCopyList[0] = btcutil.NewTx(tempTx)
		merkles := BuildMerkleTreeStore(txCopyList)
		merkleRootHash := *merkles[len(merkles)-1]

		signatureOutput := coinbaseTx.TxOut[2]
		parsedScript, err := txscript.ParseScript(signatureOutput.PkScript)
		if nil != err {
			str := "block has invalid miner signature - failed to parse script"
			return ruleError(ErrScriptValidation, str)
		}
		if len(parsedScript) < 2 || parsedScript[0].Opcode != "OP_RETURN" {
			str := "block has invalid miner signature - signature missing payload"
			return ruleError(ErrScriptValidation, str)
		}
		signature := parsedScript[1].Data

		isValid, err := checkBlockSignature(minerAddress.EncodeAddress(), merkleRootHash.Bytes(), signature, b.chainParams)

		if nil != err || !isValid {
			str := "block has invalid miner signature - signature mismatch"
			return ruleError(ErrScriptValidation, str)
		}

		// use permission manaer to check permission
		if !permissionManager.CheckPermission(dbTx, minerAddress.EncodeAddress(), permission.MinerMarker) {
			str := fmt.Sprintf("address(%s) does not have miner permission", minerAddress.EncodeAddress())
			return ruleError(ErrScriptValidation, str)
		}

		return nil
	})

	return err
}

func (b *BlockChain) CheckWriterPermission(tx *btcutil.Tx, utxoView *UtxoViewpoint) error {

	err := b.db.View(func(dbTx database.Tx) error {
		if !b.permissionManager.IsPermissionEnabled(dbTx, permission.WriterMarker) {
			return nil
		}

		txInputs := tx.MsgTx().TxIn

		for _, txIn := range txInputs {
			originTxHash := &txIn.PreviousOutPoint.Hash
			originTxIndex := txIn.PreviousOutPoint.Index
			txEntry := utxoView.LookupEntry(originTxHash)

			if txEntry == nil {
				str := fmt.Sprintf("unable to find input "+
					"transaction %v referenced from "+
					"transaction %v", originTxHash,
					tx.Sha())
				return ruleError(ErrMissingTx, str)
			}

			// Ensure the referenced input transaction public key
			// script is available.
			pkScript := txEntry.PkScriptByIndex(originTxIndex)
			if pkScript == nil {
				str := fmt.Sprintf("unable to find unspent "+
					"output %v script referenced from "+
					"transaction %s:%d",
					txIn.PreviousOutPoint, tx.Sha(),
					txIn.Sequence)

				return ruleError(ErrBadTxInput, str)
			}

			// extract sender's addresses
			_, addresses, _, err := txscript.ExtractPkScriptAddrs(pkScript,
				b.permissionManager.GetParam())
			if err != nil {
				return err
			}

			for _, addr := range addresses {
				// use permission manaer to check permission
				if !b.permissionManager.CheckPermission(dbTx, addr.EncodeAddress(), permission.WriterMarker) {
					str := fmt.Sprintf("address(%s) does not have writer permission", addr.EncodeAddress())
					return ruleError(ErrScriptValidation, str)
				}
			}
		}

		// pass permission verification
		return nil

	})

	// return error
	return err
}
