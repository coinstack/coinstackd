// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ism

import (
	"os"
	"path/filepath"
	"testing"

	"bytes"

	"github.com/coinstack/coinstackd/database"
	_ "github.com/coinstack/coinstackd/database/ffldb"
	"github.com/coinstack/coinstackd/wire"
	"github.com/btcsuite/btclog"
)

const (
	ismDbType       = "ffldb"
	ismBlockDataNet = wire.MainNet
)

func init() {
	backendLogger := btclog.NewDefaultBackendLogger()
	_ = btclog.NewSubsystemLogger(backendLogger, "")
	UseLogger(btclog.NewSubsystemLogger(backendLogger, "TEST-ISM: "))
}

func TestISMState(t *testing.T) {
	// create test context
	dbPath := filepath.Join(os.TempDir(), "test-ismindex")
	_ = os.RemoveAll(dbPath)
	idb, err := database.Create(ismDbType, dbPath, ismBlockDataNet)
	if err != nil {
		t.Errorf("Failed to create test database (%s) %v", ismDbType, err)
		return
	}
	defer os.RemoveAll(dbPath)
	defer idb.Close()

	t.Log("testing ISM state")

	// create indexer and test
	ismState := NewState()
	idb.Update(func(tx database.Tx) error {
		ismState.Create(tx)

		ismState.NewStage(tx, []byte("newblock"))
		t.Log("newblock>")
		ismState.SetItem(tx, []byte("foo"), []byte("bar"))
		t.Log(string(ismState.GetItem(tx, []byte("foo"))))
		if ismState.GetItem(tx, []byte("foo2")) != nil {
			t.Log(string(ismState.GetItem(tx, []byte("foo2"))))
			t.Error("invalid item value")
		}

		ismState.NewStage(tx, []byte("newblock2"))
		t.Log("newblock2>")
		ismState.SetItem(tx, []byte("foo2"), []byte("bar2"))
		t.Log(string(ismState.GetItem(tx, []byte("foo2"))))
		t.Log(string(ismState.GetItem(tx, []byte("foo"))))

		ismState.UndoStage(tx, []byte("newblock2"), []byte("newblock"))
		t.Log("rolled back>")
		t.Log(string(ismState.GetItem(tx, []byte("foo"))))
		t.Log(string(ismState.GetItem(tx, []byte("foo2"))))
		if ismState.GetItem(tx, []byte("foo2")) != nil {
			t.Log(string(ismState.GetItem(tx, []byte("foo2"))))
			t.Error("rollback did not happen")
		}

		item := ismState.GetInstanceItem(tx, []byte("testinstance"), []byte("testitem"))
		if nil != item {
			t.Error("item not nil")
		}

		ismState.CreateInstance(tx, []byte("testinstance"))
		item = ismState.GetInstanceItem(tx, []byte("testinstance"), []byte("testitem"))
		if nil != item {
			t.Error("item not nil")
		}

		ismState.SetInstanceItem(tx, []byte("testinstance"), []byte("foo"), []byte("test instance item"))
		item = ismState.GetInstanceItem(tx, []byte("testinstance"), []byte("foo"))
		t.Log(string(item))
		err = ismState.Commit(tx, []byte("testinstance"))
		if nil != err {
			t.Error("failed to commit")
		}

		ismState.NewStage(tx, []byte("newblock3"))
		t.Log("newblock3>")
		item = ismState.GetInstanceItem(tx, []byte("testinstance"), []byte("foo"))
		t.Log(string(item))

		ismState.CreateInstance(tx, []byte("testinstance2"))
		item = ismState.GetInstanceItem(tx, []byte("testinstance2"), []byte("testitem2"))
		if nil != item {
			t.Error("item not nil")
		}

		ismState.SetInstanceItem(tx, []byte("testinstance2"), []byte("testitem2"), []byte("test instance item2"))
		item = ismState.GetInstanceItem(tx, []byte("testinstance2"), []byte("testitem2"))
		t.Log(string(item))
		if nil == item {
			t.Error("item nil")
		}

		ismState.SetInstanceItem(tx, []byte("testinstance"), []byte("foo"), []byte("test instance item2"))
		ismState.SetInstanceItem(tx, []byte("testinstance"), []byte("foo"), []byte("test instance item3"))
		ismState.DelInstanceItem(tx, []byte("testinstance"), []byte("foo"))
		item = ismState.GetInstanceItem(tx, []byte("testinstance"), []byte("foo"))
		t.Logf("`%s`", string(item))
		if nil != item {
			t.Error("`foo` is not deleted")
		}

		err = ismState.Commit(tx, []byte("testinstance"))
		if nil != err {
			t.Error("failed to commit")
		}

		ismState.UndoStage(tx, []byte("newblock3"), []byte("newblock"))
		t.Log("rolled back2>")
		item = ismState.GetInstanceItem(tx, []byte("testinstance2"), []byte("testitem2"))
		if nil != item {
			t.Error("item not nil")
		}

		item = ismState.GetInstanceItem(tx, []byte("testinstance"), []byte("foo"))
		if "test instance item" != string(item) {
			t.Error("item not rolled back")
		}

		t.Log(string(ismState.getCurrentUndoStage(tx)))

		ismState.CreateInstance(tx, []byte("testinstance2"))
		ismState.SetInstanceItem(tx, []byte("testinstance2"), []byte("testitem3"), []byte("test instance item3"))
		t.Log(string(ismState.GetInstanceItem(tx, []byte("testinstance2"), []byte("testitem3"))))
		err = ismState.Commit(tx, []byte("testinstance2"))

		ismState.CreateInstance(tx, []byte("testinstance3"))
		ismState.SetInstanceItem(tx, []byte("testinstance3"), []byte("testitem4"), []byte("test instance item4"))
		err = ismState.Commit(tx, []byte("testinstance3"))

		ismState.NewStage(tx, []byte("newblock4"))
		item = ismState.GetInstanceItem(tx, []byte("testinstance3"), []byte("testitem4"))
		if nil == item {
			t.Error("item nil")
		}
		ismState.SetInstanceItem(tx, []byte("testinstance3"), []byte("testitem4"), []byte("test instance item5"))
		ismState.Rollback(tx, []byte("testinstance3"))

		if "test instance item5" == string(ismState.GetInstanceItem(tx, []byte("testinstance3"), []byte("testitem4"))) {
			t.Error("item not rolled back")
		}

		if "test instance item3" != string(ismState.GetInstanceItem(tx, []byte("testinstance2"), []byte("testitem3"))) {
			t.Log(string(ismState.GetInstanceItem(tx, []byte("testinstance2"), []byte("testitem3"))))
			t.Error("item not persistent")
		}

		instance4 := []byte("testinstance4")
		sameKey := []byte("same key")
		ismState.CreateInstance(tx, instance4)
		ismState.SetInstanceItem(tx, instance4, sameKey, []byte("one"))
		ismState.Commit(tx, instance4)

		instance5 := []byte("testinstance5")
		ismState.CreateInstance(tx, instance5)
		ismState.SetInstanceItem(tx, instance5, sameKey, []byte("two"))
		ismState.Commit(tx, instance5)

		ismState.SetInstanceItem(tx, []byte("testinstance"), []byte("foo"), []byte("test instance item3"))
		ismState.Commit(tx, []byte("testinstance"))

		t.Log(string(ismState.getCurrentUndoStage(tx)))

		stage5 := []byte("newblock5")
		ismState.NewStage(tx, stage5)
		t.Log(string(stage5), ">")
		t.Log("current undo stage: ", string(ismState.getCurrentUndoStage(tx)))

		ismState.SetInstanceItem(tx, instance4, sameKey, []byte("three"))
		ismState.SetInstanceItem(tx, instance4, sameKey, []byte("third"))
		ismState.Commit(tx, instance4)

		ismState.SetInstanceItem(tx, instance5, sameKey, []byte("four"))
		ismState.Commit(tx, instance5)

		item = ismState.GetInstanceItem(tx, []byte("testinstance"), []byte("foo"))
		t.Log(string(item))
		if bytes.Compare([]byte("test instance item3"), item) != 0 {
			t.Error("item not rolled back")
		}
		ismState.SetInstanceItem(tx, []byte("testinstance"), []byte("foo"), []byte("test instance item4"))
		item = ismState.GetInstanceItem(tx, []byte("testinstance"), []byte("foo"))
		t.Log(string(item))
		ismState.Commit(tx, []byte("testinstance"))

		ismState.UndoStage(tx, stage5, []byte("newblock4"))
		t.Log("rollback to newblock4")
		t.Log("current undo stage: ", string(ismState.getCurrentUndoStage(tx)))

		value := string(ismState.GetInstanceItem(tx, instance4, sameKey))
		t.Log("instance 4's `same key` = ", value)
		if "one" != value {
			t.Error("item not rolled back")
		}
		value = string(ismState.GetInstanceItem(tx, instance5, sameKey))
		t.Log("instance 5's `same key` = ", value)
		if "two" != value {
			t.Error("item not rolled back")
		}

		ismState.UndoStage(tx, []byte("newblock4"), []byte("newblock"))
		t.Log("rollback to newblock")
		t.Log("current undo stage: ", string(ismState.getCurrentUndoStage(tx)))

		if bytes.Compare([]byte("newblock"), ismState.getCurrentUndoStage(tx)) != 0 {
			t.Error("item not rolled back")
		}
		value = string(ismState.GetInstanceItem(tx, instance4, sameKey))
		t.Logf("instance 4's `same key` = `%s`", value)
		if value != "" {
			t.Error("item not rolled back")
		}
		item = ismState.GetInstanceItem(tx, []byte("testinstance"), []byte("foo"))
		t.Log(string(item))
		if bytes.Compare([]byte("test instance item"), item) != 0 {
			t.Error("item not rolled back")
		}

		return nil
	})

	ismState = NewState()
	idb.Update(func(tx database.Tx) error {
		ismState.Create(tx)
		if string(ismState.getCurrentUndoStage(tx)) != "newblock" {
			t.Log(string(ismState.getCurrentUndoStage(tx)))
			t.Error("stage mismatch")
		}
		return nil
	})

}

func TestStageInheritance(t *testing.T) {
	log.SetLevel(btclog.DebugLvl)

	// create test context
	dbPath := filepath.Join(os.TempDir(), "test-ismindex")
	_ = os.RemoveAll(dbPath)
	idb, err := database.Create(ismDbType, dbPath, ismBlockDataNet)
	if err != nil {
		t.Errorf("Failed to create test database (%s) %v", ismDbType, err)
		return
	}
	defer os.RemoveAll(dbPath)
	defer idb.Close()

	err = idb.Update(func(tx database.Tx) error {
		ismState := NewState()
		ismState.Create(tx)
		ismState.NewStage(tx, []byte("newblock"))

		instanceID := []byte("testinstance")
		ismState.CreateInstance(tx, instanceID)
		ismState.SetInstanceItem(tx, instanceID, []byte("testkey"), []byte("testvalue"))

		t.Log(string(ismState.GetInstanceItem(tx, instanceID, []byte("testkey"))))

		ismState.Commit(tx, instanceID)

		e := ismState.NewStage(tx, []byte("newblock2"))
		if e != nil {
			t.Error("failed to create a new stage")
		}

		if string(ismState.GetInstanceItem(tx, instanceID, []byte("testkey"))) != "testvalue" {
			t.Error("instance value not inherited")
		}

		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestUndoSerialization(t *testing.T) {
	before := undoEntry{
		instance: []byte("test_instance1"),
		key:      []byte("testitem_1"),
		before:   []byte("before1"),
		after:    []byte("after1"),
	}

	serialized := marshalUndo(&before)
	if serialized == nil || len(serialized) < 4 {
		t.Error("failed to serialize")
	}

	after := unmarshalUndo(serialized)
	if string(after.instance) != "test_instance1" {
		t.Log(string(after.instance))
		t.Error("failed to deserialize")
	}
	if string(after.key) != "testitem_1" {
		t.Error("failed to deserialize")
	}
	if string(after.before) != "before1" {
		t.Error("failed to deserialize")
	}
	if string(after.after) != "after1" {
		t.Error("failed to deserialize")
	}

	before = undoEntry{
		instance: nil,
		key:      []byte("testitem_1"),
		before:   nil,
		after:    []byte("after1"),
	}

	serialized = marshalUndo(&before)
	after = unmarshalUndo(serialized)
	if after.instance != nil {
		t.Log(string(after.instance))
		t.Error("failed to deserialize")
	}
	if string(after.key) != "testitem_1" {
		t.Error("failed to deserialize")
	}
	if after.before != nil {
		t.Error("failed to deserialize")
	}
	if string(after.after) != "after1" {
		t.Error("failed to deserialize")
	}

}

func TestUndoLog(t *testing.T) {
	t.Log("testing undo log")

	// create test context
	dbPath := filepath.Join(os.TempDir(), "test-ismindex")
	_ = os.RemoveAll(dbPath)
	idb, err := database.Create(ismDbType, dbPath, ismBlockDataNet)
	if err != nil {
		t.Errorf("Failed to create test database (%s) %v", ismDbType, err)
		return
	}
	defer os.RemoveAll(dbPath)
	defer idb.Close()

	err = idb.Update(func(tx database.Tx) error {
		ismState := NewState()
		ismState.Create(tx)

		// try writing undo stages
		if nil != ismState.getCurrentUndoStage(tx) {
			t.Error("invalid undo stage")
		}
		ismState.nextUndoStage(tx, []byte("stage1"))
		if "stage1" != string(ismState.getCurrentUndoStage(tx)) {
			t.Error("invalid undo stage")
		}
		ismState.nextUndoStage(tx, []byte("stage2"))
		if "stage2" != string(ismState.getCurrentUndoStage(tx)) {
			t.Error("invalid undo stage")
		}
		ismState.nextUndoStage(tx, []byte("stage3"))
		if "stage3" != string(ismState.getCurrentUndoStage(tx)) {
			t.Error("invalid undo stage")
		}
		ismState.nextUndoStage(tx, []byte("stage4"))
		if "stage4" != string(ismState.getCurrentUndoStage(tx)) {
			t.Error("invalid undo stage")
		}

		// try truncate backward
		ismState.truncateUndos(tx, []byte("stage4"), []byte("stage3"))
		if "stage3" != string(ismState.getCurrentUndoStage(tx)) {
			t.Error("invalid undo stage")
		}
		ismState.truncateUndos(tx, []byte("stage3"), []byte("stage2"))
		if "stage2" != string(ismState.getCurrentUndoStage(tx)) {
			t.Error("invalid undo stage")
		}
		ismState.truncateUndos(tx, []byte("stage2"), []byte("stage1"))
		if "stage1" != string(ismState.getCurrentUndoStage(tx)) {
			t.Error("invalid undo stage")
		}
		ismState.truncateUndos(tx, []byte("stage1"), nil)
		if nil != ismState.getCurrentUndoStage(tx) {
			stageKey := ismState.getCurrentUndoStage(tx)
			t.Log(string(stageKey))
			t.Error("invalid undo stage")
		}

		// write sequential undo log entries
		ismState.nextUndoStage(tx, []byte("stage1"))
		ismState.addUndo(tx, &undoEntry{
			instance: []byte("test_instance1"),
			key:      []byte("testitem_1"),
			before:   []byte("before1"),
			after:    []byte("after1"),
		}, 0)

		ismState.nextUndoStage(tx, []byte("stage2"))
		ismState.addUndo(tx, &undoEntry{
			instance: []byte("test_instance1"),
			key:      []byte("testitem_1"),
			before:   []byte("before2"),
			after:    []byte("after2"),
		}, 0)
		ismState.addUndo(tx, &undoEntry{
			instance: []byte("test_instance1"),
			key:      []byte("testitem_2"),
			before:   []byte("before2"),
			after:    []byte("after2"),
		}, 1)

		ismState.nextUndoStage(tx, []byte("stage3"))
		ismState.addUndo(tx, &undoEntry{
			instance: []byte("test_instance1"),
			key:      []byte("testitem_1"),
			before:   []byte("before3"),
			after:    []byte("after3"),
		}, 0)
		ismState.addUndo(tx, &undoEntry{
			instance: []byte("test_instance1"),
			key:      []byte("testitem_2"),
			before:   []byte("before3"),
			after:    []byte("after3"),
		}, 1)
		ismState.addUndo(tx, &undoEntry{
			instance: []byte("test_instance1"),
			key:      []byte("testitem_3"),
			before:   []byte("before3"),
			after:    []byte("after3"),
		}, 2)

		// read & apply
		if "stage3" != string(ismState.getCurrentUndoStage(tx)) {
			t.Error("invalid undo stage")
		}

		entries, e := ismState.fetchUndos(tx)
		if nil != e {
			t.Error("failed to fetch undo entries")
		}
		if len(entries) != 3 {
			t.Error("failed to fetch undo entries")
		}
		if string(entries[0].key) != "testitem_3" || string(entries[0].after) != "after3" || string(entries[0].before) != "before3" || string(entries[0].instance) != "test_instance1" {
			t.Error("invalid undo log entry")
		}

		if string(entries[1].key) != "testitem_2" || string(entries[1].after) != "after3" || string(entries[1].before) != "before3" || string(entries[1].instance) != "test_instance1" {
			t.Error("invalid undo log entry")
		}

		if string(entries[2].key) != "testitem_1" || string(entries[2].after) != "after3" || string(entries[2].before) != "before3" || string(entries[2].instance) != "test_instance1" {
			t.Error("invalid undo log entry")
		}

		ismState.truncateUndos(tx, []byte("stage3"), []byte("stage2"))

		if "stage2" != string(ismState.getCurrentUndoStage(tx)) {
			t.Error("invalid undo stage")
		}

		entries, e = ismState.fetchUndos(tx)
		if nil != e {
			t.Error("failed to fetch undo entries")
		}
		if len(entries) != 2 {
			t.Error("failed to fetch undo entries")
		}

		if string(entries[0].key) != "testitem_2" || string(entries[0].after) != "after2" || string(entries[0].before) != "before2" || string(entries[0].instance) != "test_instance1" {
			t.Error("invalid undo log entry")
		}

		if string(entries[1].key) != "testitem_1" || string(entries[1].after) != "after2" || string(entries[1].before) != "before2" || string(entries[1].instance) != "test_instance1" {
			t.Error("invalid undo log entry")
		}

		ismState.truncateUndos(tx, []byte("stage2"), []byte("stage1"))

		if "stage1" != string(ismState.getCurrentUndoStage(tx)) {
			t.Error("invalid undo stage")
		}

		entries, e = ismState.fetchUndos(tx)
		if nil != e {
			t.Error("failed to fetch undo entries")
		}
		if len(entries) != 1 {
			t.Error("failed to fetch undo entries")
		}

		if string(entries[0].key) != "testitem_1" || string(entries[0].after) != "after1" || string(entries[0].before) != "before1" || string(entries[0].instance) != "test_instance1" {
			t.Error("invalid undo log entry")
		}

		ismState.truncateUndos(tx, []byte("stage1"), nil)

		if nil != ismState.getCurrentUndoStage(tx) {
			t.Error("invalid undo stage")
		}

		return nil
	})
	if err != nil {
		t.Error(err)
	}
}

func TestDelInstanceItem(t *testing.T) {
	// create test context
	dbPath := filepath.Join(os.TempDir(), "test-ismindex")
	_ = os.RemoveAll(dbPath)
	idb, err := database.Create(ismDbType, dbPath, ismBlockDataNet)
	if err != nil {
		t.Errorf("Failed to create test database (%s) %v", ismDbType, err)
		return
	}
	defer os.RemoveAll(dbPath)
	defer idb.Close()

	t.Log("testing ISM state")

	var testDelInstance = []byte("delete")
	var key = []byte("foo")

	// create indexer and test
	ismState := NewState()
	idb.Update(func(tx database.Tx) error {
		ismState.Create(tx)

		ismState.NewStage(tx, []byte("newblock1"))
		t.Log("newblock1>")
		ismState.CreateInstance(tx, testDelInstance)
		ismState.SetInstanceItem(tx, testDelInstance, key, []byte("bar"))
		val := ismState.GetInstanceItem(tx, testDelInstance, key)
		if string(val) != "bar" {
			t.Errorf("failed to set instance item: `%s`", string(val))
		}
		t.Log(string(val))
		ismState.Commit(tx, testDelInstance)

		ismState.NewStage(tx, []byte("newblock2"))
		t.Log("newblock2>")
		t.Logf("delelete instance item: `%s`", key)
		ismState.SetInstanceItem(tx, testDelInstance, key, []byte("boo"))
		val = ismState.GetInstanceItem(tx, testDelInstance, key)
		t.Log(string(val))
		ismState.DelInstanceItem(tx, testDelInstance, key)
		val = ismState.GetInstanceItem(tx, testDelInstance, key)
		if val != nil {
			t.Errorf("failed to delete instance item: `%s`", string(val))
		}
		ismState.DelInstanceItem(tx, testDelInstance, []byte("foo2"))
		ismState.Commit(tx, testDelInstance)

		ismState.UndoStage(tx, []byte("newblock2"), []byte("newblock1"))
		t.Log("rolled back>")
		val = ismState.GetInstanceItem(tx, testDelInstance, key)
		if val == nil {
			t.Error("rollback did not happend")
		}
		if string(val) != "bar" {
			t.Error("rollback did not happend")
		}
		t.Log(string(val))
		ismState.Commit(tx, testDelInstance)

		ismState.NewStage(tx, []byte("newblock3"))
		t.Log("newblock3>")
		t.Logf("delelete instance item: `%s`", key)
		ismState.DelInstanceItem(tx, testDelInstance, key)
		ismState.SetInstanceItem(tx, testDelInstance, key, []byte("boo"))
		ismState.SetInstanceItem(tx, testDelInstance, key, []byte("bxx"))
		val = ismState.GetInstanceItem(tx, testDelInstance, key)
		if val == nil {
			t.Errorf("failed to set instance item: `%s`", string(val))
		}
		t.Log(string(val))
		ismState.Commit(tx, testDelInstance)

		ismState.UndoStage(tx, []byte("newblock3"), []byte("newblock2"))
		val = ismState.GetInstanceItem(tx, testDelInstance, key)
		if val == nil {
			t.Error("rollback did not happend")
		}
		if string(val) != "bar" {
			t.Error("rollback did not happend")
		}
		t.Log(string(val))
		ismState.Commit(tx, testDelInstance)

		return nil
	})
}
