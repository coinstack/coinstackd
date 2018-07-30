// Copyright (c) 2016 BLOCKO INC.
package peer

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"strings"

	"github.com/coinstack/coinstackd/btcec"
	"github.com/coinstack/coinstackd/chaincfg"
	"github.com/coinstack/coinstackd/coinstack/permission"
	"github.com/coinstack/coinstackd/database"
	"github.com/coinstack/coinstackd/wire"
	"github.com/coinstack/btcutil"
	"github.com/coinstack/btcutil/base58"
)

func generatePeerSignature(signingKey *btcec.PrivateKey, addrMe wire.NetAddress) (string, error) {
	// serialize address of me
	byteBuffer := bytes.Buffer{}
	err := gob.NewEncoder(&byteBuffer).Encode(addrMe)

	if nil != err {
		return "", err
	}

	// sign the serialized address
	signature, err := btcec.SignCompact(btcec.S256(), signingKey, byteBuffer.Bytes(), true)
	if nil != err {
		return "", err
	}

	return base58.Encode(signature), nil
}

func checkPeerPermission(permissionManager permission.Manager, dbTx database.Tx,
	msg *wire.MsgVersion, chainParams *chaincfg.Params) error {

	if !permissionManager.IsPermissionEnabled(dbTx, permission.NodeMarker) {
		log.Debug("Checking Node Permission is Disabled")
		return nil
	}

	sign := ""
	strChunks := strings.Split(msg.UserAgent, "/")
	for _, chunk := range strChunks {
		keyValue := strings.Split(chunk, ":")
		// skip unsupported formate of item
		if len(keyValue) != 2 {
			continue
		}
		// get sign value
		if strings.Compare(keyValue[0], "sign") == 0 {
			sign = keyValue[1]
		}
	}
	// because there is no sign, reject the opposit
	if sign == "" {
		return errors.New("identity info (pubkey, sign) is missing")
	}

	// serialize address of you
	byteBuffer := bytes.Buffer{}
	err := gob.NewEncoder(&byteBuffer).Encode(msg.AddrYou)
	if nil != err {
		return fmt.Errorf("failed to serialize addrYou: %s", err)
	}

	// verify sing of the opposite
	publicKey, valid, err := btcec.RecoverCompact(btcec.S256(), base58.Decode(sign), byteBuffer.Bytes())
	if nil != err || valid != true {
		return fmt.Errorf("failed to verify sign: %s", err)
	}

	// extract address
	signatureAddress, _ := btcutil.NewAddressPubKey(publicKey.SerializeCompressed(),
		chainParams)

	// use permission manaer to check permission
	if !permissionManager.CheckPermission(dbTx, signatureAddress.EncodeAddress(), permission.NodeMarker) {
		return fmt.Errorf("node %s is disconnected by missing node permission", signatureAddress.EncodeAddress())
	}

	log.Debugf("Node(%s) pass checking node permission", signatureAddress.EncodeAddress())

	return nil
}
