// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/coinstack/coinstackd/blockchain"
	"github.com/coinstack/coinstackd/chaincfg"
	"github.com/coinstack/coinstackd/coinstack/permission"
	"github.com/coinstack/coinstackd/database"
	"github.com/coinstack/coinstackd/txscript"
	"github.com/coinstack/coinstackd/wire"
	"github.com/coinstack/btcutil"
)

const (
	permIndexName = "permission index"
)

var (
	permMarkerMagic = []byte{0x4f, 0x4c} // OL
	permIndexKey    = []byte("permidx")

	enabledBucketKey = []byte("enabledPerm")

	permBucketKey = []byte("permission")

	aliasBucketKey = []byte("alias")

	valueKey   = []byte("_value")
	historyKey = []byte("_history")
)

// PermIndex manages blockchain permissions.
// Teere are 3 types of commands to handle a permission
//  - Enable / disable permission = 0x01 (00000001)
//      Using this, admin can select an use of writer/miner/node permission
//  - Set permission to address = 0x02 (00000010)
//  - Set alias = 0x04 (00000100)
//
// There are 4 types of permissions;
// 	- AdminPermission  = 0x01 (00000001)
//  - WriterPermission = 0x02 (00000010)
//  - MinerPermission  = 0x04 (00000100)
//  - NodePermission   = 0x08 (00001000)
//
// A structure for handling permission looks like this;
//
// permMarkerMagic(4f4c) + version(0001) + command(01) + data
// for example
//  - to enable permission; WRITER/MINER(2+4=6)
//     4f4c 0001 01 06
//  - to give permission MINER/NODE(4+8=12) to 1L9KStnjKLvx4B3cjvF7kwodhQQ4NoZC23
//     4f4c 0001 02 12 1L9KStnjKLvx4B3cjvF7kwodhQQ4NoZC23
//  - to set alias a 'tester' to pubkey; ApUgFzJSLeBNt6X0BF3maPBPebuetvKhZTTx2XwDbn52
//     4f4c 0001 04 ApUgFzJSLeBNt6X0BF3maPBPebuetvKhZTTx2XwDbn52 tester
//     a lengh of public key is fixed to 33 bytes (compressed pubkey)
type PermIndex struct {
	chainParams *chaincfg.Params
}

// Ensure the PermIndex type implements the Indexer interface.
var _ Indexer = (*PermIndex)(nil)

func (idx *PermIndex) Init(bestHeight int32) error {
	// Nothing to do.
	return nil
}

func (idx *PermIndex) Key() []byte {
	return permIndexKey
}

func (idx *PermIndex) Name() string {
	return permIndexName
}

func (idx *PermIndex) Create(dbTx database.Tx) error {
	// create root bucket
	permIdxBucket, err := dbTx.Metadata().CreateBucket(permIndexKey)
	if nil != err {
		return err
	}

	// create enabled permission bucket under the root bucket
	_, err = permIdxBucket.CreateBucket(enabledBucketKey)
	if nil != err {
		return err
	}

	// create permission bucket under the root bucket
	_, err = permIdxBucket.CreateBucket(permBucketKey)
	if nil != err {
		return err
	}

	// create alias bucket under the root bucket
	_, err = permIdxBucket.CreateBucket(aliasBucketKey)
	if nil != err {
		return err
	}

	return nil
}

func (idx *PermIndex) ConnectBlock(dbTx database.Tx, block *btcutil.Block, view *blockchain.UtxoViewpoint) error {
	// handle genesis block
	if block.Sha().IsEqual(idx.chainParams.GenesisHash) {
		tx := block.Transactions()[0]
		for _, txOut := range tx.MsgTx().TxOut {
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(txOut.PkScript,
				idx.chainParams)
			if err != nil {
				continue
			}

			for _, addr := range addrs {
				err = idx.setPermission(dbTx, tx.Sha(), addr.EncodeAddress(), permission.AdminMarker)
				if err != nil {
					log.Errorf("Fail to Set Admin Permission in Genesis Block: %s", err)
					return err
				}
				log.Infof("Add Admin Permission to %s", addr.EncodeAddress())
			}
		}

		return nil
	}

	for _, tx := range block.Transactions() {
		// TODO error handling
		idx.processTx(dbTx, tx, view)
	}

	return nil
}

func (idx *PermIndex) DisconnectBlock(dbTx database.Tx, block *btcutil.Block, view *blockchain.UtxoViewpoint) error {

	txs := block.Transactions()

	// tx in the block have to be canceled in reverse order.
	// because there is a command to set admin permission to other user,
	// Assum there is two tx in same block; set admin to addr1 / addr1 modify some permission.
	// then second command can be executed only if addr1 has admin perm.
	// when cancel tx, indexer also check admin permission
	// so, in above case, indexer must cancel midify permission command first, and cancel set admin second
	for i := range txs {
		// reverse order
		tx := txs[len(txs)-1-i]

		idx.unprocessTx(dbTx, tx, view)
	}

	return nil
}

// checkPermissionTx method verify and find transactions to manage permission
// this returns whether an input tx is permission management command or not, and error
func (idx *PermIndex) parsePermissionTx(dbTx database.Tx, tx *btcutil.Tx,
	view *blockchain.UtxoViewpoint) (bool, *permission.Marker, error) {
	// Check output for Open Access Controls
	if len(tx.MsgTx().TxOut) < 2 {
		return false, nil, nil // ignore tx
	}
	// Examine a first output
	markerOutput := tx.MsgTx().TxOut[0]
	parsedScript, err := txscript.ParseScript(markerOutput.PkScript)
	if nil != err {
		// Since marker output has no parsable script, ignore tx
		return false, nil, nil
	}

	// Check if script has at least components
	if len(parsedScript) < 2 {
		return false, nil, nil
	}

	if parsedScript[0].Opcode != "OP_RETURN" {
		return false, nil, nil
	}

	payload := parsedScript[1].Data
	payloadLength := len(payload)
	if payloadLength < 6 {
		log.Trace("payload too short")
		return false, nil, nil
	}

	// check marker magic
	if !bytes.HasPrefix(payload, permMarkerMagic) { // stands for OL
		log.Trace("magic byte not found")
		return false, nil, nil
	}

	// Check input and ensure this tx is created by someone with permission
	granter := ""
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
			if granter == "" {
				granter = addrString
			} else if granter != addrString {
				// since granter addresses are not uniform, ignore tx
				return true, nil, fmt.Errorf("adresses for admin is not uniform. ignore tx. %s != %s",
					granter, addrString)
			}
		}
	}
	if granter == "" {
		// since granter address is not found, ignore tx
		return true, nil, fmt.Errorf("Cannot find admin address in a tx")
	}

	// check if granter has adaquete permission
	if !idx.checkPermission(dbTx, granter, permission.AdminMarker) {
		return true, nil, fmt.Errorf("Unauthorized address (%s) try to modify permission", granter)
	}

	marker := permission.Marker{}

	// parse byte data
	marker.MajorVersion = uint16(payload[2])
	marker.MinorVersion = uint16(payload[3])

	marker.CmdType = permission.Cmd(payload[4])

	// parse bytes according to the type of cmd
	if marker.CmdType == permission.EnablePermCmd {
		marker.Permission = payload[5]
	} else if marker.CmdType == permission.SetPermCmd {
		// header 5 + min address size 10 = 15
		if payloadLength < 15 {
			return true, nil,
				fmt.Errorf("Target address for set permission cmd is too short")
		}
		marker.Permission = payload[5]
		marker.Address = string(payload[6:])
	} else if marker.CmdType == permission.SetAliasCmd {
		// header 5 + min pubkey size 33 + min alias 1 = 39
		if payloadLength < 39 {
			return true, nil,
				fmt.Errorf("Data for set alias cmd is too short")
		}

		marker.PublicKey = payload[5:38]
		marker.Alias = string(payload[38:])
	} else {
		return true, nil, fmt.Errorf("Unsupported permission cmd type: %d", payload[5])
	}

	return true, &marker, nil
}

func (idx *PermIndex) processTx(dbTx database.Tx, tx *btcutil.Tx, view *blockchain.UtxoViewpoint) error {
	// Check a tx. whether tx belongs to permission management tx or not
	isPermTx, permMarker, err := idx.parsePermissionTx(dbTx, tx, view)

	if isPermTx == false {
		// tx is not permission management tx. skip
		return nil
	} else if err != nil {
		// just print warn message and skip this tx
		log.Warnf("Skip processTx (%s), which has an invalid pemission command: %s",
			tx.Sha().String(), err)
		return nil
	}

	// version check
	if permMarker.MajorVersion == 1 && permMarker.MinorVersion == 0 {

		if permMarker.CmdType == permission.EnablePermCmd {
			err = idx.setEnabledPermission(dbTx, tx.Sha(), permMarker.Permission)
			if err != nil {
				return err
			}
		} else if permMarker.CmdType == permission.SetPermCmd {
			err = idx.setPermission(dbTx, tx.Sha(), permMarker.Address, permMarker.Permission)
			if err != nil {
				return err
			}
		} else if permMarker.CmdType == permission.SetAliasCmd {
			err = idx.setAlias(dbTx, tx.Sha(), permMarker.Alias, permMarker.PublicKey)
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("unsupported cmd type")
		}
	} else {
		log.Warnf("Skip processTx (%s), unsupported permission command version: %d.%d",
			tx.Sha().String(), permMarker.MajorVersion, permMarker.MinorVersion)
		return nil
	}

	return nil
}

func (idx *PermIndex) unprocessTx(dbTx database.Tx, tx *btcutil.Tx, view *blockchain.UtxoViewpoint) error {

	// Check a tx. whether tx belongs to permission management tx or not
	isPermTx, permMarker, err := idx.parsePermissionTx(dbTx, tx, view)

	if isPermTx == false {
		// tx is not permission management tx. skip
		return nil
	} else if err != nil {
		// just print warn message and skip this tx
		log.Warnf("Skip unprocessTx (%s), which has an invalid pemission command: %s",
			tx.Sha().String(), err)
		return nil
	}

	// version check
	if permMarker.MajorVersion == 1 && permMarker.MinorVersion == 0 {

		if permMarker.CmdType == permission.EnablePermCmd {
			err = idx.cancelLastEnabledPermission(dbTx, tx.Sha(), permMarker.Permission)
			if err != nil {
				return err
			}
		} else if permMarker.CmdType == permission.SetPermCmd {
			err = idx.cancelLastPermission(dbTx, tx.Sha(), permMarker.Address, permMarker.Permission)
			if err != nil {
				return err
			}
		} else if permMarker.CmdType == permission.SetAliasCmd {
			err = idx.cancelLastAlias(dbTx, tx.Sha(), permMarker.Alias, permMarker.PublicKey)
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("unsupported cmd type")
		}
	} else {
		log.Warnf("Skip unprocessTx (%s), unsupported permission command version: %d.%d",
			tx.Sha().String(), permMarker.MajorVersion, permMarker.MinorVersion)
		return nil
	}

	return nil
}

func checkEnabledPermissionCmd(permissions byte) error {
	// admin permission cannot be turned on/off
	if (permissions & permission.AdminMarker) == 1 {
		return errors.New("Admin Permission cannot be modified")
	}
	return nil
}

func (idx *PermIndex) setEnabledPermission(dbTx database.Tx, txSha *wire.ShaHash,
	permissions byte) error {

	err := checkEnabledPermissionCmd(permissions)
	if err != nil {
		// just print warn message and skip this tx
		log.Warnf("Skip Tx (%s), which has an invalid enable pemission command: %s",
			txSha.String(), err)

		return nil
	}

	log.Infof("Set Enabled Permission %b at tx: %s",
		permissions, txSha.String())

	// fetch permission bucket
	enabledPermBucket := dbTx.Metadata().Bucket(permIndexKey).Bucket(enabledBucketKey)

	// get previous permission
	previousPermission := idx.getEnabledPermission(dbTx)

	// set enabled permission
	err = enabledPermBucket.Put(valueKey, []byte{permissions})
	if nil != err {
		return err
	}

	history := enabledPermBucket.Get(historyKey)

	if nil == history {
		history = []byte{previousPermission}
	} else {
		history = append(history, previousPermission)
	}

	// update history
	err = enabledPermBucket.Put(historyKey, history)
	if nil != err {
		return err
	}

	return nil
}

func (idx *PermIndex) cancelLastEnabledPermission(dbTx database.Tx, txSha *wire.ShaHash,
	permissions byte) error {

	err := checkEnabledPermissionCmd(permissions)
	if err != nil {
		// just print warn message and skip this tx
		log.Warnf("Skip Tx (%s), which has an invalid enable pemission command: %s",
			txSha.String(), err)

		return nil
	}

	log.Infof("Cancel Enabled Permission %b at tx: %s",
		permissions, txSha.String())

	// fetch permission bucket
	enabledPermBucket := dbTx.Metadata().Bucket(permIndexKey).Bucket(enabledBucketKey)

	// get enabled permission change history
	history := enabledPermBucket.Get(historyKey)

	if nil == history || len(history) == 0 {
		// set an empty enabled permission
		err := enabledPermBucket.Put(valueKey, []byte{})
		if nil != err {
			return err
		}
	} else {
		// get a previous item
		previousPermission := history[len(history)-1]

		// set enabled permission using the last one
		err := enabledPermBucket.Put(valueKey, []byte{previousPermission})
		if nil != err {
			return err
		}

		// update history except the last one
		err = enabledPermBucket.Put(historyKey, history[:len(history)-1])
		if nil != err {
			return err
		}
	}

	return nil
}

func (idx *PermIndex) GetEnabledPermission(dbTx database.Tx) byte {
	return idx.getEnabledPermission(dbTx)
}

func (idx *PermIndex) getEnabledPermission(dbTx database.Tx) byte {
	enabledPermBucket := dbTx.Metadata().Bucket(permIndexKey).Bucket(enabledBucketKey)

	perm := enabledPermBucket.Get(valueKey)

	if perm != nil && len(perm) != 0 {
		return perm[0]
	}

	return 0x0
}

func checkSetPermissionCmd(addr string) error {
	if len(addr) == 0 {
		return fmt.Errorf("Alias name cannot be empty")
	}

	return nil
}

func (idx *PermIndex) setPermission(dbTx database.Tx, txSha *wire.ShaHash,
	addr string, permissions byte) error {

	err := checkSetPermissionCmd(addr)
	if err != nil {
		// just print warn message and skip this tx
		log.Warnf("Skip Tx (%s), which has an invalid set pemission command: %s",
			txSha.String(), err)

		return nil
	}

	log.Infof("Set Permission %s to %s at tx: %s",
		permission.ConvertToString(permissions), addr, txSha.String())

	// fetch permission bucket
	permBucket := dbTx.Metadata().Bucket(permIndexKey).Bucket(permBucketKey)

	addrBucket, err := permBucket.CreateBucketIfNotExists([]byte(addr))
	if nil != err {
		return err
	}

	// get previous permission
	previousPermission := idx.getPermission(dbTx, addr)

	// set enabled permission
	err = addrBucket.Put(valueKey, []byte{permissions})
	if nil != err {
		return err
	}

	history := addrBucket.Get(historyKey)

	if nil == history {
		history = []byte{previousPermission}
	} else {
		history = append(history, previousPermission)
	}

	// update history
	err = addrBucket.Put(historyKey, history)
	if nil != err {
		return err
	}

	return nil
}

func (idx *PermIndex) cancelLastPermission(dbTx database.Tx, txSha *wire.ShaHash,
	addr string, permissions byte) error {

	err := checkSetPermissionCmd(addr)
	if err != nil {
		// just print warn message and skip this tx
		log.Warnf("Skip Tx (%s), which has an invalid set pemission command: %s",
			txSha.String(), err)

		return nil
	}

	log.Infof("Cancel Permission %b to %s at tx: %s",
		permissions, addr, txSha.String())

	// fetch permission bucket
	addrBucket := dbTx.Metadata().Bucket(permIndexKey).Bucket(permBucketKey).Bucket([]byte(addr))

	if addrBucket == nil {
		return errors.New("An address does not exist")
	}

	// get change history
	history := addrBucket.Get(historyKey)

	if nil == history || len(history) == 0 {
		// set an empty enabled permission
		err := addrBucket.Put(valueKey, []byte{})
		if nil != err {
			return err
		}
	} else {
		// get a previous item
		previousPermission := history[len(history)-1]

		// set enabled permission using the last one
		err := addrBucket.Put(valueKey, []byte{previousPermission})
		if nil != err {
			return err
		}

		// update history except the last one
		err = addrBucket.Put(historyKey, history[:len(history)-1])
		if nil != err {
			return err
		}
	}

	return nil
}

func (idx *PermIndex) GetPermission(dbTx database.Tx, addr string) byte {
	return idx.getPermission(dbTx, addr)
}

func (idx *PermIndex) getPermission(dbTx database.Tx, addr string) byte {
	// get permission bucket
	addrBucket := dbTx.Metadata().Bucket(permIndexKey).Bucket(permBucketKey).Bucket([]byte(addr))

	if addrBucket == nil {
		return 0x0
	}

	perm := addrBucket.Get(valueKey)

	// empty check
	if perm != nil && len(perm) != 0 {
		return perm[0]
	}

	return 0x0
}

func (idx *PermIndex) checkPermission(dbTx database.Tx, addr string, permissions byte) bool {
	// fetch permission bucket
	addrBucket := dbTx.Metadata().Bucket(permIndexKey).Bucket(permBucketKey).Bucket([]byte(addr))

	if addrBucket == nil {
		return false
	}

	storedPermission := addrBucket.Get(valueKey)

	// empty check
	if storedPermission != nil && len(storedPermission) != 0 {
		// admin always have permission
		if (storedPermission[0] & permission.AdminMarker) ==
			permission.AdminMarker {
			return true
		}
		// check permission bit
		return (storedPermission[0] & permissions) == permissions
	}

	return false
}

func (idx *PermIndex) ListAllPermission(dbTx database.Tx) (map[string]byte, error) {
	return idx.listAllPermission(dbTx)
}

func (idx *PermIndex) listAllPermission(dbTx database.Tx) (map[string]byte, error) {
	var result = make(map[string]byte)

	permBucket := dbTx.Metadata().Bucket(permIndexKey).Bucket(permBucketKey)
	err := permBucket.ForEachBucket(func(addr []byte) error {

		addrBucket := permBucket.Bucket(addr)
		if nil == addrBucket {
			return errors.New("Address bucket in iterator cannot be emtpy: " + string(addr))
		}

		perm := addrBucket.Get(valueKey)
		if perm != nil && len(perm) != 0 {
			result[string(addr)] = perm[0]
		}

		return nil
	})

	if nil != err {
		return nil, err
	}

	return result, nil
}

func checkSetAliasCmd(aliasName string, publicKey []byte) error {
	// name size check
	if len(aliasName) > permission.AliasNameMaxSize {
		return fmt.Errorf("Alias name (%s) is longer than %d",
			aliasName, permission.AliasNameMaxSize)
	} else if len(aliasName) == 0 {
		return fmt.Errorf("Alias name cannot be empty")
	} else if publicKey == nil || len(publicKey) == 0 {
		return fmt.Errorf("Public key cannot be empty")
	} else if len(publicKey) != permission.AliasPublickeySize {
		return fmt.Errorf("A length of publickey must be 33 byte")
	}
	return nil
}

func (idx *PermIndex) setAlias(dbTx database.Tx, txSha *wire.ShaHash,
	aliasName string, publicKey []byte) error {

	// check input
	err := checkSetAliasCmd(aliasName, publicKey)
	if err != nil {
		// just print warn message and skip this tx
		log.Warnf("Skip Tx (%s), which has an invalid set alias command: %s",
			txSha.String(), err)

		return nil
	}

	log.Infof("Set alias '%s -> %s' at tx: %s",
		aliasName, hex.EncodeToString(publicKey), txSha.String())

	// fetch alias bucket
	aliasIndexBucket := dbTx.Metadata().Bucket(permIndexKey).Bucket(aliasBucketKey)

	aliasNameBucket, err := aliasIndexBucket.CreateBucketIfNotExists([]byte(aliasName))
	if nil != err {
		return err
	}

	// get previous permission
	previousPublickey := idx.getAliasPublickey(dbTx, aliasName)

	// set publickey
	err = aliasNameBucket.Put(valueKey, publicKey)
	if nil != err {
		return err
	}

	history := aliasNameBucket.Get(historyKey)

	if nil == history {
		history = previousPublickey
	} else {
		history = append(history, previousPublickey...)
	}

	// update history
	err = aliasNameBucket.Put(historyKey, history)
	if nil != err {
		return err
	}

	return nil
}

func (idx *PermIndex) cancelLastAlias(dbTx database.Tx, txSha *wire.ShaHash,
	aliasName string, publicKey []byte) error {

	// check input
	err := checkSetAliasCmd(aliasName, publicKey)
	if err != nil {
		// just print warn message and skip this tx
		log.Warnf("Skip Tx (%s), which has an invalid set alias command: %s",
			txSha.String(), err)

		return nil
	}

	log.Infof("Cancel alias '%s -> %s' at tx: %s",
		aliasName, hex.EncodeToString(publicKey), txSha.String())

	// fetch alias bucket
	aliasIndexBucket := dbTx.Metadata().Bucket(permIndexKey).Bucket(aliasBucketKey)
	aliasBucket, err := aliasIndexBucket.CreateBucketIfNotExists([]byte(aliasName))
	if nil != err {
		return err
	}

	// get change history
	history := aliasBucket.Get(historyKey)

	if nil == history || len(history) == 0 {
		// set an empty enabled permission
		err := aliasBucket.Put(valueKey, []byte{})
		if nil != err {
			return err
		}
	} else {
		// get a previous item
		previousPermission := history[len(history)-permission.AliasPublickeySize:]

		// set enabled permission using the last one
		err := aliasBucket.Put(valueKey, previousPermission)
		if nil != err {
			return err
		}

		fmt.Println(len(history[:len(history)-permission.AliasPublickeySize]))

		// update history except the last one
		err = aliasBucket.Put(historyKey, history[:len(history)-permission.AliasPublickeySize])
		if nil != err {
			return err
		}
	}

	return nil
}

func (idx *PermIndex) GetAliasPublickey(dbTx database.Tx, aliasName string) []byte {
	return idx.getAliasPublickey(dbTx, aliasName)
}

func (idx *PermIndex) getAliasPublickey(dbTx database.Tx, aliasName string) []byte {
	// name size check
	if len(aliasName) > permission.AliasNameMaxSize {
		return nil
	} else if len(aliasName) == 0 {
		return nil
	}

	// get alias bucket
	aliasBucket := dbTx.Metadata().Bucket(permIndexKey).Bucket(aliasBucketKey).Bucket([]byte(aliasName))

	if aliasBucket == nil {
		return nil
	}

	publickey := aliasBucket.Get(valueKey)

	// empty check
	if publickey != nil && len(publickey) != 0 {
		return publickey
	}

	return nil
}

func (idx *PermIndex) ListAlias(dbTx database.Tx) (map[string][]byte, error) {
	return idx.listAlias(dbTx)
}

func (idx *PermIndex) listAlias(dbTx database.Tx) (map[string][]byte, error) {
	var result = make(map[string][]byte)

	aliasIndexBucket := dbTx.Metadata().Bucket(permIndexKey).Bucket(aliasBucketKey)

	// iterator over each alias bucket
	err := aliasIndexBucket.ForEachBucket(func(aliasName []byte) error {

		aliasBucket := aliasIndexBucket.Bucket(aliasName)
		if nil == aliasBucket {
			return errors.New("Alias bucket in iterator cannot be emtpy: " + string(aliasName))
		}

		publickey := aliasBucket.Get(valueKey)
		if publickey != nil && len(publickey) != 0 {
			result[string(aliasName)] = publickey
		}

		return nil
	})

	if nil != err {
		return nil, err
	}

	return result, nil
}

// CheckPermission is used to check an existance of permissions at a given address
func (idx *PermIndex) CheckPermission(dbTx database.Tx, addr string, permissions byte) bool {
	return idx.checkPermission(dbTx, addr, permissions)
}

func (idx *PermIndex) IsPermissionEnabled(dbTx database.Tx, permissions byte) bool {
	currentEnabledPerm := idx.getEnabledPermission(dbTx)

	if currentEnabledPerm&permission.AdminMarker == permission.AdminMarker {
		// admin has all permission
		return true
	} else if permissions&currentEnabledPerm == permissions {
		return true
	}

	return false
}

// GetParam returns a current chain parameter set
func (idx *PermIndex) GetParam() *chaincfg.Params {
	return idx.chainParams
}

// NewPermIndex is a constructor to create a new PermIndex instance
func NewPermIndex(chainParams *chaincfg.Params) *PermIndex {
	return &PermIndex{
		chainParams: chainParams,
	}
}
