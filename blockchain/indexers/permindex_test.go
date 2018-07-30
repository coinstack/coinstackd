// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package indexers

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/coinstack/coinstackd/blockchain"
	"github.com/coinstack/coinstackd/chaincfg"
	"github.com/coinstack/btcutil"

	"github.com/coinstack/coinstackd/coinstack/permission"
	"github.com/coinstack/coinstackd/database"
	_ "github.com/coinstack/coinstackd/database/ffldb"
	"github.com/coinstack/coinstackd/wire"
)

const (
	dbType       = "ffldb"
	blockDataNet = wire.MainNet
)

func TestEnablePermission(t *testing.T) {
	// create test context
	dbPath := filepath.Join(os.TempDir(), "test-pmsindex")
	_ = os.RemoveAll(dbPath)
	idb, err := database.Create(dbType, dbPath, blockDataNet)
	if err != nil {
		t.Errorf("Failed to create test database (%s) %v", dbType, err)
		return
	}
	defer os.RemoveAll(dbPath)
	defer idb.Close()

	t.Log("testing permission index")

	// create indexer and test
	permIndexer := NewPermIndex(nil)
	dummyTxid, _ := wire.NewShaHashFromStr("d029fe0623d90cc3542f33f0b284e57065261dcfe8893ab5e996dac6490905cb")

	idb.Update(func(tx database.Tx) error {
		permIndexer.Create(tx)

		return nil
	})

	// check empty status
	idb.View(func(tx database.Tx) error {
		perm := permIndexer.getEnabledPermission(tx)
		if perm != 0x0 {
			t.Errorf("Invalid Permission is Enabled %08b", perm)
		}

		return nil
	})

	// writer permission turned on;
	// _value = WRITER
	// _history = []
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.setEnabledPermission(tx, dummyTxid, permission.WriterMarker)
		if err != nil {
			t.Error("Fail to enable permission")
		}
		perm := permIndexer.getEnabledPermission(tx)
		if perm&permission.WriterMarker != permission.WriterMarker {
			t.Errorf("Invalid Permission is Enabled %08b != %08b",
				perm, permission.WriterMarker)
		}

		return nil
	})

	// node and miner permission turned on
	// _value = NODE|MINER
	// _history = WRITER
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.setEnabledPermission(tx, dummyTxid,
			permission.NodeMarker|permission.MinerMarker)
		if err != nil {
			t.Error("Fail to enable permission")
		}
		perm := permIndexer.getEnabledPermission(tx)
		if (perm&permission.WriterMarker == permission.WriterMarker) ||
			(perm&permission.NodeMarker != permission.NodeMarker) ||
			(perm&permission.MinerMarker != permission.MinerMarker) {
			t.Errorf("Invalid Permission is Enabled %08b", perm)
		}

		return nil
	})

	// only miner permission turned on
	// _value = MINER
	// _history = WRITER, NODE|MINER
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.setEnabledPermission(tx, dummyTxid, permission.MinerMarker)
		if err != nil {
			t.Error("Fail to enable perm")
		}
		perm := permIndexer.getEnabledPermission(tx)
		if (perm&permission.WriterMarker == permission.WriterMarker) ||
			(perm&permission.NodeMarker == permission.NodeMarker) ||
			(perm&permission.MinerMarker != permission.MinerMarker) {
			t.Errorf("Invalid Permission is Enabled %08b", perm)
		}

		return nil
	})

	// rollback one stage
	// _value = NODE|MINER
	// _history = WRITER
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.cancelLastEnabledPermission(tx, dummyTxid, permission.MinerMarker)
		if err != nil {
			t.Error("Fail to cancel perm")
		}
		perm := permIndexer.getEnabledPermission(tx)
		if (perm&permission.WriterMarker == permission.WriterMarker) ||
			(perm&permission.NodeMarker != permission.NodeMarker) ||
			(perm&permission.MinerMarker != permission.MinerMarker) {
			t.Errorf("Invalid Permission is Enabled %08b", perm)
		}

		return nil
	})

	// rollback one more stage
	// _value = WRITER
	// _history = []
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.cancelLastEnabledPermission(tx, dummyTxid,
			permission.NodeMarker|permission.MinerMarker)
		if err != nil {
			t.Error("Fail to cancel perm")
		}
		perm := permIndexer.getEnabledPermission(tx)
		if perm&permission.WriterMarker != permission.WriterMarker {
			t.Errorf("Invalid Permission is Enabled %08b", perm)
		}
		return nil
	})

	// rollback two more stage
	// _value = []
	// _history = []
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.cancelLastEnabledPermission(tx, dummyTxid, permission.WriterMarker)
		if err != nil {
			t.Error("Fail to cancel perm")
		}
		perm := permIndexer.getEnabledPermission(tx)
		if perm != 0x0 {
			t.Errorf("Invalid Permission is Enabled %08b", perm)
		}
		return nil
	})

	// admin permission cannot be modified
	idb.Update(func(tx database.Tx) error {
		permIndexer.setEnabledPermission(tx, dummyTxid, permission.AdminMarker)
		if permIndexer.getEnabledPermission(tx)&permission.AdminMarker == permission.AdminMarker {
			t.Error("Admin is modified")
		}
		return nil
	})
}

func TestGivePermission(t *testing.T) {
	// create test context
	dbPath := filepath.Join(os.TempDir(), "test-pmsindex")
	_ = os.RemoveAll(dbPath)
	idb, err := database.Create(dbType, dbPath, blockDataNet)
	if err != nil {
		t.Errorf("Failed to create test database (%s) %v", dbType, err)
		return
	}
	defer os.RemoveAll(dbPath)
	defer idb.Close()

	t.Log("testing permission index")

	// create indexer and test
	permIndexer := NewPermIndex(nil)
	dummyTxid, _ := wire.NewShaHashFromStr("d029fe0623d90cc3542f33f0b284e57065261dcfe8893ab5e996dac6490905cb")

	// initialize an index
	idb.Update(func(tx database.Tx) error {
		permIndexer.Create(tx)
		return nil
	})

	// set a permission
	// user1: _value = ADMIN / _history = []
	idb.Update(func(tx database.Tx) error {
		permIndexer.setPermission(tx, dummyTxid, "user1", permission.AdminMarker)
		if !permIndexer.checkPermission(tx, "user1", permission.AdminMarker) {
			t.Error("failed to check permission")
		}
		if permIndexer.getPermission(tx, "user1") != permission.AdminMarker {
			t.Error("invalid permission")
		}
		return nil
	})

	// cancel the permission
	// user1: _value = [] / _history = []
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.cancelLastPermission(tx, dummyTxid, "user1", permission.AdminMarker)
		if err != nil {
			t.Error("fail to cancel permission")
		}
		if permIndexer.checkPermission(tx, "user1", permission.AdminMarker) {
			t.Error("failed to check permission")
		}
		return nil
	})

	// give multiple permissions
	// user1: _value = ADMIN|WRITER / _history = []
	idb.Update(func(tx database.Tx) error {
		permIndexer.setPermission(tx, dummyTxid, "user1",
			permission.AdminMarker|permission.WriterMarker)

		if !permIndexer.checkPermission(tx, "user1",
			permission.AdminMarker|permission.WriterMarker) {
			t.Error("failed to check permission")
		}
		return nil
	})

	// make multiple users and set those permissions
	// user1: _value = ADMIN|WRITER / _history = []
	// user2: _value = WRITER / _history = []
	// user3: _value = MINER|NODE / _history = []
	idb.Update(func(tx database.Tx) error {
		permIndexer.setPermission(tx, dummyTxid, "user2", permission.WriterMarker)
		permIndexer.setPermission(tx, dummyTxid, "user3", permission.MinerMarker|permission.NodeMarker)

		addrPermMap, _ := permIndexer.listAllPermission(tx)
		for addr, perm := range addrPermMap {
			switch addr {
			case "user1":
				if perm&permission.AdminMarker != permission.AdminMarker {
					t.Error("Invalid Permission set")
				}
			case "user2":
				if perm&permission.WriterMarker != permission.WriterMarker {
					t.Error("Invalid Permission set")
				}
			case "user3":
				if perm&permission.MinerMarker != permission.MinerMarker &&
					perm&permission.NodeMarker != permission.NodeMarker {
					t.Error("Invalid Permission set")
				}
			default:
				t.Error("Undefined address is exist")
			}
		}

		return nil
	})
}

func TestSetAlias(t *testing.T) {
	// create test context
	dbPath := filepath.Join(os.TempDir(), "test-pmsindex")
	_ = os.RemoveAll(dbPath)
	idb, err := database.Create(dbType, dbPath, blockDataNet)
	if err != nil {
		t.Errorf("Failed to create test database (%s) %v", dbType, err)
		return
	}
	defer os.RemoveAll(dbPath)
	defer idb.Close()

	t.Log("testing alias index")

	// create indexer and test
	permIndexer := NewPermIndex(nil)
	dummyTxid, _ := wire.NewShaHashFromStr("d029fe0623d90cc3542f33f0b284e57065261dcfe8893ab5e996dac6490905cb")

	pubkeyA1, _ := base64.StdEncoding.DecodeString("AsGVppKZ8euJPIldr88Nd/C5fRRfxcod6cB145DDM4+k")
	pubkeyA2, _ := base64.StdEncoding.DecodeString("A5ZBiJy7X9pT6iL4kT1hr/UBwJ2pjTZP5Mu6CViN1C6s")
	pubkeyA3, _ := base64.StdEncoding.DecodeString("ApUgFzJSLeBNt6X0BF3maPBPebuetvKhZTTx2XwDbn52")

	pubkeyB1, _ := base64.StdEncoding.DecodeString("A2pqG/VMYsUrJyN4wyCY3ZkPz16kPpvKcHtu1NUhTcrH")
	pubkeyC1, _ := base64.StdEncoding.DecodeString("A0OS/tSUu7LIy/SEB5v93CwazNpRVkEjOkmSvCyCyV1+")

	// initialize an index
	idb.Update(func(tx database.Tx) error {
		permIndexer.Create(tx)
		return nil
	})

	// get empty
	idb.View(func(tx database.Tx) error {
		if nil != permIndexer.getAliasPublickey(tx, "userA") {
			t.Error("fetched public key is invalid")
		}
		return nil
	})

	// set an alias
	// userA: _value = pubkeyA1 / _history = []
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.setAlias(tx, dummyTxid, "userA", pubkeyA1)
		if err != nil {
			t.Error("failed to set alias")
		}
		if bytes.Compare(pubkeyA1, permIndexer.getAliasPublickey(tx, "userA")) != 0 {
			t.Error("fetched public key is invalid")
		}

		ret, _ := permIndexer.listAlias(tx)

		if len(ret) != 1 {
			t.Error("there must be one alias item")
		}

		return nil
	})

	// set another alias; userB
	// userA: _value = pubkeyA1 / _history = []
	// userB: _value = pubkeyB1 / _history = []
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.setAlias(tx, dummyTxid, "userB", pubkeyB1)
		if err != nil {
			t.Error("failed to set alias")
		}
		if bytes.Compare(pubkeyB1, permIndexer.getAliasPublickey(tx, "userB")) != 0 {
			t.Error("fetched public key is invalid")
		}

		ret, _ := permIndexer.listAlias(tx)

		if len(ret) != 2 {
			t.Error("there must be two alias item")
		}

		return nil
	})

	// cancel alias of userB
	// userA: _value = pubkeyA1 / _history = []
	// userB: _value = [] / _history = []
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.cancelLastAlias(tx, dummyTxid, "userB", pubkeyB1)
		if err != nil {
			t.Error("failed to cancel alias")
		}

		if nil != permIndexer.getAliasPublickey(tx, "userB") {
			t.Error("fetched public key is invalid")
		}

		ret, _ := permIndexer.listAlias(tx)

		if len(ret) != 1 {
			t.Error("there must be one alias item")
		}

		return nil
	})

	// set another alias; userC
	// userA: _value = pubkeyA1 / _history = []
	// userC: _value = pubkeyC1 / _history = []
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.setAlias(tx, dummyTxid, "userC", pubkeyC1)
		if err != nil {
			t.Error("failed to set alias")
		}
		if bytes.Compare(pubkeyC1, permIndexer.getAliasPublickey(tx, "userC")) != 0 {
			t.Error("fetched public key is invalid")
		}

		ret, _ := permIndexer.listAlias(tx)

		if len(ret) != 2 {
			t.Error("there must be two alias item")
		}

		return nil
	})

	// update an existing alias; userA
	// userA: _value = pubkeyA2 / _history = pubkeyA1
	// userC: _value = pubkeyC1 / _history = []
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.setAlias(tx, dummyTxid, "userA", pubkeyA2)
		if err != nil {
			t.Error("failed to set alias")
		}
		if bytes.Compare(pubkeyA2, permIndexer.getAliasPublickey(tx, "userA")) != 0 {
			t.Error("fetched public key is invalid")
		}

		ret, _ := permIndexer.listAlias(tx)

		if len(ret) != 2 {
			t.Error("there must be two alias item")
		}

		return nil
	})

	// update an existing alias; userA
	// userA: _value = pubkeyA3 / _history = pubkeyA1->pubkeyA2
	// userC: _value = pubkeyC1 / _history = []
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.setAlias(tx, dummyTxid, "userA", pubkeyA3)
		if err != nil {
			t.Error("failed to set alias")
		}
		if bytes.Compare(pubkeyA3, permIndexer.getAliasPublickey(tx, "userA")) != 0 {
			t.Error("fetched public key is invalid")
		}

		return nil
	})

	// cancel alias of userA
	// userA: _value = pubkeyA2 / _history = pubkeyA1
	// userC: _value = pubkeyC1 / _history = []
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.cancelLastAlias(tx, dummyTxid, "userA", pubkeyA3)
		if err != nil {
			t.Error("failed to cancel alias")
		}

		if bytes.Compare(pubkeyA2, permIndexer.getAliasPublickey(tx, "userA")) != 0 {
			t.Error("fetched public key is invalid")
		}

		return nil
	})

	// cancel alias of userA
	// userA: _value = pubkeyA1 / _history = []
	// userC: _value = pubkeyC1 / _history = []
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.cancelLastAlias(tx, dummyTxid, "userA", pubkeyA2)
		if err != nil {
			t.Error("failed to cancel alias")
		}

		if bytes.Compare(pubkeyA1, permIndexer.getAliasPublickey(tx, "userA")) != 0 {
			t.Error("fetched public key is invalid")
		}

		return nil
	})

	// cancel alias of userA
	// userA: _value = [] / _history = []
	// userC: _value = pubkeyC1 / _history = []
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.cancelLastAlias(tx, dummyTxid, "userA", pubkeyA1)
		if err != nil {
			t.Error("failed to cancel alias")
		}

		if nil != permIndexer.getAliasPublickey(tx, "userA") {
			t.Error("fetched public key is invalid")
		}

		return nil
	})

	// check alias name size limit
	idb.Update(func(tx database.Tx) error {
		// exceed max name length limit
		longAlias := "thisAliasIsExceedMaxSize16"
		err := permIndexer.setAlias(tx, dummyTxid, longAlias, pubkeyA1)
		if err != nil && permIndexer.getAliasPublickey(tx, longAlias) != nil {
			t.Errorf(fmt.Sprintf("alias name exceed max size limit: %d",
				permission.AliasNameMaxSize))
		}
		// test empty alias
		err = permIndexer.setAlias(tx, dummyTxid, "", pubkeyA1)
		if err != nil && permIndexer.getAliasPublickey(tx, "") != nil {
			t.Errorf("empty alias name must be blocked")
		}
		return nil
	})
}

func TestProcessTx(t *testing.T) {

	// create test context
	dbPath := filepath.Join(os.TempDir(), "test-pmsindex")
	_ = os.RemoveAll(dbPath)
	idb, err := database.Create(dbType, dbPath, blockDataNet)
	if err != nil {
		t.Errorf("Failed to create test database (%s) %v", dbType, err)
		return
	}
	defer os.RemoveAll(dbPath)
	defer idb.Close()

	t.Log("testing permission index")

	// initialize
	// create indexer
	permIndexer := NewPermIndex(&chaincfg.MainNetParams)
	myTxid, _ := wire.NewShaHashFromStr("d029fe0623d90cc3542f33f0b284e57065261dcfe8893ab5e996dac6490905cb")

	// initialize an permission index
	idb.Update(func(tx database.Tx) error {
		permIndexer.Create(tx)

		// gives admin permission to 1J7~
		permIndexer.setPermission(tx, myTxid, "1J7gq86KsfcYAbguEj9u2jjYH6gYqJyhc1", permission.AdminMarker)
		return nil
	})

	// utxo transaction
	byteTxUtxo, _ := hex.DecodeString("0100000001ae4ebef04865e5125cfbff299ced1c25fa9db0da4d23e81dc4aa2a5951a2bcf1000000006b483045022100a2566240a8fc577fcb9a8afac1f6d57aacb61a5e2871afe5a73863d38fa995bf02206e060a8a947942e5726524b27a0567c0ddaf4659c597e03e6a8e7d4e19bfdb7a0121024ee6f2bbb3ce78c6f34f78834b5d3568b5ffd85f8bf8d502a7ac326bceca01e7ffffffff0280969800000000001976a914bbbde1db19680c21c3f1bc9f8a3c3954567d289688ac30a99fa30b0000001976a914b9087aacc9c624e4ba48766994f37b7ac607418388ac00000000")
	txUtxo, _ := btcutil.NewTxFromBytes(byteTxUtxo)

	view := blockchain.NewUtxoViewpoint()
	view.AddTxOuts(txUtxo, 100)

	// test to put normal tx that does not effect on permission index
	//
	// unsupported data format
	// OP_RETURN 74657374 //test
	byteTxUnsupportedFormat, _ := hex.DecodeString("01000000010f92675173e3870883e888bae5bce397f83934d8b1af6280c1013e4e303c3c0e000000006b483045022100a42ec92c69ae8c98370ef97313b91f1220b8718c23f3eda0c3bcec282537bc3302201452db759146ee112284d0776c38b9a1b9aee4fc3f60360fd6294ab60c8d40280121029e166b59f6f3e19745b789a8f2b4aecd47203694ab7f9945043b98c859cd7b9cffffffff020000000000000000066a0474657374706f9800000000001976a914bbbde1db19680c21c3f1bc9f8a3c3954567d289688ac00000000")
	txUnsupportedFormat, _ := btcutil.NewTxFromBytes(byteTxUnsupportedFormat)

	idb.Update(func(tx database.Tx) error {
		err := permIndexer.processTx(tx, txUnsupportedFormat, view)
		if err != nil {
			t.Error(err)
		}

		// check empty enabled permission status
		permission := permIndexer.getEnabledPermission(tx)
		if permission != 0x0 {
			t.Errorf("Invalid Permission is Enabled %08b", permission)
		}

		permMap, _ := permIndexer.listAllPermission(tx)
		if len(permMap) != 1 {
			t.Error("address in permission list must be one")
		}
		aliasMap, _ := permIndexer.listAlias(tx)
		if len(aliasMap) != 0 {
			t.Error("alias list must be empty")
		}

		return nil
	})

	// test to put enable permission tx
	//
	// enable permission command; writer and miner
	// OP_RETURN 4f4C 0001 01 04 //enable_permission_command writer|miner
	byteTxEnablePerm, _ := hex.DecodeString("01000000010f92675173e3870883e888bae5bce397f83934d8b1af6280c1013e4e303c3c0e000000006b483045022100a804448d13e93bb3b2eec65f8e2930473d64147f5b56c4f7efc7c2fcbfe3e6dd022033924935f2c1279f34f8a1bacf32ea3c7ff07793dc8e626e3de7489c02af1edf0121029e166b59f6f3e19745b789a8f2b4aecd47203694ab7f9945043b98c859cd7b9cffffffff020000000000000000086a064f4c01000106706f9800000000001976a914bbbde1db19680c21c3f1bc9f8a3c3954567d289688ac00000000")
	txEnablePerm, _ := btcutil.NewTxFromBytes(byteTxEnablePerm)

	idb.Update(func(tx database.Tx) error {
		err := permIndexer.processTx(tx, txEnablePerm, view)
		if err != nil {
			t.Error(err)
		}

		// check empty enabled permission status
		perm := permIndexer.getEnabledPermission(tx)
		if perm&(permission.WriterMarker|permission.MinerMarker) !=
			(permission.WriterMarker | permission.MinerMarker) {
			t.Errorf("Invalid Permission is Enabled %08b !=%08b ", perm,
				(permission.WriterMarker | permission.MinerMarker))
		}

		permMap, _ := permIndexer.listAllPermission(tx)
		if len(permMap) != 1 {
			t.Error("address in permission list must be one")
		}
		aliasMap, _ := permIndexer.listAlias(tx)
		if len(aliasMap) != 0 {
			t.Error("alias list must be empty")
		}

		return nil
	})

	// test to set permission command; node and miner
	//
	// OP_RETURN 4f4C 0001 02 0c 314c394b53746e6a4b4c7678344233636a7646376b776f64685151344e6f5a433233
	// set_permission_command node|miner 1L9KStnjKLvx4B3cjvF7kwodhQQ4NoZC23
	byteTxSetPerm, _ := hex.DecodeString("01000000010f92675173e3870883e888bae5bce397f83934d8b1af6280c1013e4e303c3c0e000000006b483045022100dedac78909239b6942f9c45a3f50d2ff210667b40c78b5701551f7ae3b44c0bc02207b0be3b8dd591b3d69d1b9be9f561fb62e0d5b038cefb0edba5de4ccee8448260121029e166b59f6f3e19745b789a8f2b4aecd47203694ab7f9945043b98c859cd7b9cffffffff0200000000000000002a6a284f4c0100020c314c394b53746e6a4b4c7678344233636a7646376b776f64685151344e6f5a433233706f9800000000001976a914bbbde1db19680c21c3f1bc9f8a3c3954567d289688ac00000000")
	txSetPerm, _ := btcutil.NewTxFromBytes(byteTxSetPerm)

	idb.Update(func(tx database.Tx) error {
		err := permIndexer.processTx(tx, txSetPerm, view)
		if err != nil {
			t.Error(err)
		}

		// check permission of an address
		perm := permIndexer.getPermission(tx, "1L9KStnjKLvx4B3cjvF7kwodhQQ4NoZC23")

		if perm&(permission.NodeMarker|permission.MinerMarker) !=
			(permission.NodeMarker | permission.MinerMarker) {
			t.Errorf("Invalid Permission is Enabled %08b !=%08b ", perm,
				(permission.NodeMarker | permission.MinerMarker))
		}

		permMap, _ := permIndexer.listAllPermission(tx)
		if len(permMap) != 2 {
			t.Error("address in permission list must be two")
		}
		aliasMap, _ := permIndexer.listAlias(tx)
		if len(aliasMap) != 0 {
			t.Error("alias list must be empty")
		}

		return nil
	})

	// test to set alias command; tester -> ApUbF....
	//
	// OP_RETURN 4f4C 0001 03 0295201732522de04db7a5f4045de668f04f79bb9eb6f2a16534f1d97c036e7e76 746573746572
	// set_alias_command ApUgFzJSLeBNt6X0BF3maPBPebuetvKhZTTx2XwDbn52 tester
	byteTxSetAlias, _ := hex.DecodeString("01000000010f92675173e3870883e888bae5bce397f83934d8b1af6280c1013e4e303c3c0e000000006a47304402206fa7048c59d2d0857e67bb630354a228e678cd1f810411dae890038bec0e00a802204b80470935fa60f20d61492a7efc98fdd3c9e76cae77815d965c43bfb063a4030121029e166b59f6f3e19745b789a8f2b4aecd47203694ab7f9945043b98c859cd7b9cffffffff0200000000000000002e6a2c4f4c0100030295201732522de04db7a5f4045de668f04f79bb9eb6f2a16534f1d97c036e7e76746573746572706f9800000000001976a914bbbde1db19680c21c3f1bc9f8a3c3954567d289688ac00000000")
	txSetAlias, _ := btcutil.NewTxFromBytes(byteTxSetAlias)

	idb.Update(func(tx database.Tx) error {
		err := permIndexer.processTx(tx, txSetAlias, view)
		if err != nil {
			t.Error(err)
		}

		// get publickey of a given alias
		fetchedPublickey := permIndexer.getAliasPublickey(tx, "tester")
		strPubkey := "ApUgFzJSLeBNt6X0BF3maPBPebuetvKhZTTx2XwDbn52"
		bytePubkey, _ := base64.StdEncoding.DecodeString(strPubkey)
		if !bytes.Equal(fetchedPublickey, bytePubkey) {
			t.Errorf("Invalid publickey is set to alias %x != %s",
				fetchedPublickey, strPubkey)
		}

		permMap, _ := permIndexer.listAllPermission(tx)
		if len(permMap) != 2 {
			t.Error("address in permission list must be two")
		}
		aliasMap, _ := permIndexer.listAlias(tx)
		if len(aliasMap) != 1 {
			t.Error("a length of alias list must be one")
		}

		return nil
	})

	// unprocess tx; set alias command
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.unprocessTx(tx, txSetAlias, view)
		if err != nil {
			t.Error(err)
		}

		// get publickey of a given alias
		fetchedPublickey := permIndexer.getAliasPublickey(tx, "tester")

		if nil != fetchedPublickey {
			t.Errorf("publickey must be empty, but %x",
				fetchedPublickey)
		}

		permMap, _ := permIndexer.listAllPermission(tx)
		if len(permMap) != 2 {
			t.Error("address in permission list must be two")
		}
		aliasMap, _ := permIndexer.listAlias(tx)
		if len(aliasMap) != 0 {
			t.Error("a length of alias list must be zero")
		}

		return nil
	})

	// unprocess set permission command
	idb.Update(func(tx database.Tx) error {
		err := permIndexer.unprocessTx(tx, txSetPerm, view)
		if err != nil {
			t.Error(err)
		}

		// check permission of an address
		perm := permIndexer.getPermission(tx, "1L9KStnjKLvx4B3cjvF7kwodhQQ4NoZC23")

		if perm&(permission.NodeMarker|permission.MinerMarker) !=
			0x0 {
			t.Errorf("Invalid Permission is Enabled %08b !=%08b ", perm, 0x0)
		}

		permMap, _ := permIndexer.listAllPermission(tx)
		if len(permMap) != 2 {
			t.Error("address in permission list must be two")
		}
		aliasMap, _ := permIndexer.listAlias(tx)
		if len(aliasMap) != 0 {
			t.Error("alias list must be empty")
		}

		return nil
	})
}
