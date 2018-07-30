// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ism

import (
	"encoding/binary"
	"errors"

	"bytes"

	"github.com/coinstack/coinstackd/blockchain"
	"github.com/coinstack/coinstackd/coinstack/client"
	"github.com/coinstack/coinstackd/coinstack/crypto"
	"github.com/coinstack/coinstackd/database"
	"github.com/coinstack/coinstackd/database/ffldb"
	"github.com/coinstack/coinstackd/event"
)

var (
	ismStateKey   = []byte("ismState")
	blockStageKey = []byte("ismStateKey")

	eventBucketKey = []byte("event")

	// undo implementations
	undoStageKey  = []byte("undostagekey")
	undoBucketKey = []byte("undobucketKey")
)

type batchType int

// nolint: golint
const (
	IsmBatchKeys batchType = iota
	IsmBatchRemove
)

type State struct {
	batch                 map[string][]database.Bucket
	EphemeralEnabled      bool
	ephemeral             bool
	ephemeralStore        map[string][]map[string][]byte
	encryptKey            []byte
	lStateCache           *LStateCache
	modified              map[string]struct{}
	modifiedMapByInstance map[string]*modifiedMap

	// undo implementations
	currentUndoStage []byte
	changeNumber     uint32

	Stat client.ContractStat
}

func NewState() *State {
	return &State{
		batch:          make(map[string][]database.Bucket),
		ephemeral:      false,
		ephemeralStore: make(map[string][]map[string][]byte),
	}
}

func (state *State) Create(dbTx database.Tx) error {
	_, err := dbTx.Metadata().CreateBucket(ismStateKey)
	if nil != err {
		return err
	}

	// create a new bucket
	_, err = dbTx.Metadata().Bucket(ismStateKey).CreateBucket(blockStageKey)
	if nil != err {
		return err
	}

	// create undo bucket
	_, err = dbTx.Metadata().Bucket(ismStateKey).CreateBucket(undoBucketKey)
	if nil != err {
		return err
	}

	_, err = dbTx.Metadata().CreateBucket(eventBucketKey)

	return err
}

func (state *State) Init() {
	state.lStateCache = NewLStateCache(20)
}

func (state *State) LoadEventListeners(dbTx database.Tx) error {
	bucket := dbTx.Metadata().Bucket(eventBucketKey)
	if bucket == nil {
		_, err := dbTx.Metadata().CreateBucket(eventBucketKey)
		return err
	}
	return bucket.ForEach(func(k, v []byte) error {
		eventType, url := deserializeEventListener(k)
		event.AddEventListener(eventType, url, "")
		return nil
	})
}

func (state *State) NewStage(dbTx database.Tx, stageKey []byte) error {
	// make room for undo
	err := state.nextUndoStage(dbTx, stageKey)
	if nil != err {
		return err
	}

	state.changeNumber = 0
	state.batch = make(map[string][]database.Bucket)
	state.modified = make(map[string]struct{})
	state.modifiedMapByInstance = make(map[string]*modifiedMap)
	if state.EphemeralEnabled {
		state.ephemeral = false
		state.ephemeralStore = make(map[string][]map[string][]byte)
	}
	return nil
}

func (state *State) UndoStage(dbTx database.Tx, currentStageKey []byte, previousStageKey []byte) error {
	// apply undo log
	entries, err := state.fetchUndos(dbTx)
	if nil != err {
		return err
	}

	bucket := dbTx.Metadata().Bucket(ismStateKey).Bucket(blockStageKey)

	for _, entry := range entries {
		if entry.instance != nil {
			instanceBucket := state.GetInstance(dbTx, entry.instance)
			if entry.before != nil {
				err := instanceBucket.Put(entry.key, entry.before)
				if nil != err {
					return err
				}
			} else {
				err := instanceBucket.Delete(entry.key)
				if nil != err {
					return err
				}
			}
		} else {
			if entry.before != nil {
				err := bucket.Put(entry.key, entry.before)
				if nil != err {
					return err
				}
			} else {
				err := bucket.Delete(entry.key)
				if nil != err {
					return err
				}
			}
		}
	}
	state.truncateUndos(dbTx, currentStageKey, previousStageKey)
	state.changeNumber = 0
	state.batch = make(map[string][]database.Bucket)
	state.modified = make(map[string]struct{})
	state.modifiedMapByInstance = make(map[string]*modifiedMap)
	if state.EphemeralEnabled {
		state.ephemeral = false
		state.ephemeralStore = make(map[string][]map[string][]byte)
	}

	if state.lStateCache != nil {
		state.lStateCache.Purge()
	}

	return nil
}

func (state *State) PurgeStage(dbTx database.Tx, height int32) {
	log.Debugf("remove the undo stage: %d height", height)
	hash, err := blockchain.DbFetchHashByHeight(dbTx, height)
	if err == nil {
		err = dbTx.Metadata().Bucket(ismStateKey).Bucket(undoBucketKey).DeleteBucket(hash.Bytes())
	}
	if err != nil {
		log.Warn(err)
	}
}

func (state *State) HasUndoStage(dbTx database.Tx, height int32) bool {
	hash, err := blockchain.DbFetchHashByHeight(dbTx, height)
	if err == nil {
		b := dbTx.Metadata().Bucket(ismStateKey).Bucket(undoBucketKey).Bucket(hash.Bytes())
		return b != nil
	}
	return false
}

func (state *State) GetItem(dbTx database.Tx, key []byte) []byte {
	return dbTx.Metadata().Bucket(ismStateKey).Bucket(blockStageKey).Get(key)
}

func (state *State) SetItem(dbTx database.Tx, key []byte, value []byte) error {
	bucket := dbTx.Metadata().Bucket(ismStateKey).Bucket(blockStageKey)
	previous := bucket.Get(key)

	err := bucket.Put(key, value)
	if nil != err {
		return err
	}

	if _, ok := state.modified[string(key)]; !ok {
		state.addUndo(dbTx,
			&undoEntry{
				instance: nil,
				key:      key,
				before:   previous,
				after:    nil,
			},
			state.changeNumber)
		state.modified[string(key)] = struct{}{}
		state.changeNumber++
	}
	return nil
}

func (state *State) CreateInstance(dbTx database.Tx, instance []byte) {
	dbTx.Metadata().Bucket(ismStateKey).Bucket(blockStageKey).CreateBucket(instance)
}

func (state *State) CreateInstanceIfNotExist(dbTx database.Tx, instance []byte) error {
	_, err := dbTx.Metadata().Bucket(ismStateKey).Bucket(blockStageKey).CreateBucketIfNotExists(instance)
	return err
}

func (state *State) RemoveInstance(dbTx database.Tx, instance []byte) error {
	return dbTx.Metadata().Bucket(ismStateKey).Bucket(blockStageKey).DeleteBucket(instance)
}

func (state *State) HasInstance(dbTx database.Tx, instance []byte) bool {
	return state.GetInstance(dbTx, instance) != nil
}

func (state *State) SetInstanceEncryptKey(key []byte) {
	state.encryptKey = key
}

func encryptValue(key, value []byte) []byte {
	if len(key) == 0 {
		return value
	}
	encryptedValue, err := crypto.Encrypt(value, key)
	if err != nil {
		log.Debug(err)
		return value
	}
	return encryptedValue
}

func decryptValue(key, value []byte) []byte {
	if len(key) == 0 || len(value) < 32 {
		return value
	}
	decryptedValue, err := crypto.Decrypt(value, key)
	if err != nil {
		log.Debug(err)
		return value
	}
	return decryptedValue
}

func (state *State) GetInstanceItem(dbTx database.Tx, instance []byte, key []byte) []byte {
	var value []byte

	instanceBatch, ok := state.batch[string(instance)]
	if ok {
		if value = instanceBatch[IsmBatchRemove].Get(key); value != nil {
			return nil
		}
		if value = instanceBatch[IsmBatchKeys].Get(key); value != nil {
			return value
		}
	}
	if state.ephemeral {
		ephemeralBatch, ok := state.ephemeralStore[string(instance)]
		if ok {
			_, ok := ephemeralBatch[IsmBatchRemove][string(key)]
			if ok {
				return nil
			}
			value, ok = ephemeralBatch[IsmBatchKeys][string(key)]
			if ok {
				return value
			}
		}
	}
	instanceBucket := state.GetInstance(dbTx, instance)
	if instanceBucket == nil {
		return nil
	}
	return instanceBucket.Get(key)
}

type modifiedMap struct {
	modified map[string]struct{}
	undos    map[string]*undoMemEntry
}

func newModifiedMap() *modifiedMap {
	return &modifiedMap{
		modified: make(map[string]struct{}),
		undos:    make(map[string]*undoMemEntry),
	}
}

func (m *modifiedMap) occupy(instanceId string, undo *undoMemEntry) {
	m.modified[instanceId] = struct{}{}
	m.undos[instanceId] = undo
}

func (m *modifiedMap) contains(instanceId string) bool {
	_, ok := m.modified[instanceId]
	return ok
}

func (m *modifiedMap) popUndos() map[string]*undoMemEntry {
	undos := m.undos
	m.undos = make(map[string]*undoMemEntry)
	return undos
}

func (state *State) DelInstanceItem(dbTx database.Tx, instance []byte, key []byte) error {
	if state.EphemeralEnabled {
		return errors.New("not implemented feature(s)")
	}

	instanceBatch, ok := state.batch[string(instance)]
	if !ok {
		instanceBatch = make([]database.Bucket, 2)
		instanceBatch[IsmBatchKeys] = ffldb.NewTreapBucket()
		instanceBatch[IsmBatchRemove] = ffldb.NewTreapBucket()
		state.batch[string(instance)] = instanceBatch
	}
	instanceBatch[IsmBatchKeys].Delete(key)
	instanceBatch[IsmBatchRemove].Put(key, nil)

	modifiedMap, ok := state.modifiedMapByInstance[string(instance)]
	if !ok {
		modifiedMap = newModifiedMap()
		state.modifiedMapByInstance[string(instance)] = modifiedMap
	}
	if !modifiedMap.contains(string(key)) {
		instanceBucket := state.GetInstance(dbTx, instance)
		if instanceBucket == nil {
			return errors.New("instance not initialized")
		}
		previous := instanceBucket.Get(key)
		if previous != nil {
			modifiedMap.occupy(string(key),
				&undoMemEntry{
					&undoEntry{
						instance: instance,
						key:      key,
						before:   previous,
						after:    nil,
					},
					state.changeNumber,
				},
			)
			state.changeNumber++
		}
	}
	return nil
}

func (state *State) GetInstance(dbTx database.Tx, instance []byte) database.Bucket {
	return dbTx.Metadata().Bucket(ismStateKey).Bucket(blockStageKey).Bucket(instance)
}

func (state *State) SetInstanceItem(dbTx database.Tx, instance []byte, key []byte, value []byte) error {
	instanceBatch, ok := state.batch[string(instance)]
	if !ok {
		instanceBatch = make([]database.Bucket, 2)
		instanceBatch[IsmBatchKeys] = ffldb.NewTreapBucket()
		instanceBatch[IsmBatchRemove] = ffldb.NewTreapBucket()
		state.batch[string(instance)] = instanceBatch
	}
	instanceBatch[IsmBatchRemove].Delete(key)
	instanceBatch[IsmBatchKeys].Put(key, value)

	if state.ephemeral {
		return nil
	}

	modifiedMap, ok := state.modifiedMapByInstance[string(instance)]
	if !ok {
		modifiedMap = newModifiedMap()
		state.modifiedMapByInstance[string(instance)] = modifiedMap
	}
	if !modifiedMap.contains(string(key)) {
		instanceBucket := state.GetInstance(dbTx, instance)
		if instanceBucket == nil {
			return errors.New("instance not initialized")
		}
		previous := instanceBucket.Get(key)
		modifiedMap.occupy(string(key),
			&undoMemEntry{
				&undoEntry{
					instance: instance,
					key:      key,
					before:   previous,
					after:    nil,
				},
				state.changeNumber,
			},
		)
		state.changeNumber++
	}

	return nil
}

func (state *State) ephemeralCommit(instance []byte, instanceBatch []database.Bucket) {
	ephBatch, ok := state.ephemeralStore[string(instance)]
	if !ok {
		ephBatch = make([]map[string][]byte, 2)
		ephBatch[IsmBatchKeys] = make(map[string][]byte)
		ephBatch[IsmBatchRemove] = make(map[string][]byte)
		state.ephemeralStore[string(instance)] = ephBatch
	}
	c := instanceBatch[IsmBatchKeys].Cursor()
	for ok := c.First(); ok; ok = c.Next() {
		ephBatch[IsmBatchKeys][string(c.Key())] = c.Value()
	}
	c = instanceBatch[IsmBatchRemove].Cursor()
	for ok := c.First(); ok; ok = c.Next() {
		ephBatch[IsmBatchRemove][string(c.Key())] = c.Value()
	}
}

func (state *State) Commit(dbTx database.Tx, instance []byte) error {
	instanceBucket := state.GetInstance(dbTx, instance)
	if instanceBucket == nil {
		return errors.New("instance not initialized")
	}
	if instanceBatch, exist := state.batch[string(instance)]; exist {
		defer delete(state.batch, string(instance))
		if state.ephemeral {
			state.ephemeralCommit(instance, instanceBatch)
			return nil
		}
		c := instanceBatch[IsmBatchKeys].Cursor()
		for ok := c.First(); ok; ok = c.Next() {
			if err := instanceBucket.Put(c.Key(), c.Value()); err != nil {
				return err
			}
		}
		c = instanceBatch[IsmBatchRemove].Cursor()
		for ok := c.First(); ok; ok = c.Next() {
			if err := instanceBucket.Delete(c.Key()); err != nil {
				return err
			}
		}
		modifiedMap, ok := state.modifiedMapByInstance[string(instance)]
		if ok {
			for _, v := range modifiedMap.popUndos() {
				state.addUndo(dbTx, v.undoEntry, v.changeNumber)
			}
		}
	}
	return nil
}

func (state *State) Rollback(dbTx database.Tx, instance []byte) error {
	delete(state.batch, string(instance))
	if !state.ephemeral {
		modifiedMap, ok := state.modifiedMapByInstance[string(instance)]
		if ok {
			_ = modifiedMap.popUndos()
		}
	}
	return nil
}

func (state *State) NewEphemeralStage() {
	if state.EphemeralEnabled {
		state.ephemeral = true
	}
}

type undoEntry struct {
	instance []byte
	key      []byte
	before   []byte
	after    []byte
}

type undoMemEntry struct {
	*undoEntry
	changeNumber uint32
}

func (e *undoEntry) String() string {
	var buffer bytes.Buffer
	buffer.WriteString("key: ")
	buffer.Write(e.key)
	buffer.WriteString(", value: ")
	buffer.Write(e.before)
	return buffer.String()
}

func marshalUndo(undoItem *undoEntry) []byte {
	instanceLength := len(undoItem.instance)
	keyLength := len(undoItem.key)
	beforeLength := len(undoItem.before)
	afterLength := len(undoItem.after)

	size := 4*4 + instanceLength + keyLength + beforeLength + afterLength
	item := make([]byte, size)

	index := 0

	// instance
	binary.LittleEndian.PutUint32(item[index:], uint32(instanceLength))
	index += 4

	copy(item[index:], undoItem.instance)
	index += instanceLength

	// key
	binary.LittleEndian.PutUint32(item[index:], uint32(keyLength))
	index += 4

	copy(item[index:], undoItem.key)
	index += keyLength

	// before
	binary.LittleEndian.PutUint32(item[index:], uint32(beforeLength))
	index += 4

	copy(item[index:], undoItem.before)
	index += beforeLength

	// after
	binary.LittleEndian.PutUint32(item[index:], uint32(afterLength))
	index += 4

	copy(item[index:], undoItem.after)

	return item
}

func unmarshalUndo(item []byte) *undoEntry {
	undoItem := undoEntry{}

	index := uint32(0)
	size := binary.LittleEndian.Uint32(item[index:])
	index += 4
	if size > 0 {
		undoItem.instance = make([]byte, size)
		copy(undoItem.instance, item[index:index+size])
		index += size
	} else {
		undoItem.instance = nil
	}

	size = binary.LittleEndian.Uint32(item[index:])
	index += 4
	if size > 0 {
		undoItem.key = make([]byte, size)
		copy(undoItem.key, item[index:index+size])
		index += size
	} else {
		undoItem.key = nil
	}

	size = binary.LittleEndian.Uint32(item[index:])
	index += 4
	if size > 0 {
		undoItem.before = make([]byte, size)
		copy(undoItem.before, item[index:index+size])
		index += size
	} else {
		undoItem.before = nil
	}

	size = binary.LittleEndian.Uint32(item[index:])
	index += 4
	if size > 0 {
		undoItem.after = make([]byte, size)
		copy(undoItem.after, item[index:index+size])
	} else {
		undoItem.after = nil
	}
	return &undoItem
}

func (state *State) addUndo(dbTx database.Tx, undoItem *undoEntry, changeSequence uint32) error {
	serializedUndo := marshalUndo(undoItem)
	bucket :=
		dbTx.Metadata().Bucket(ismStateKey).Bucket(undoBucketKey).Bucket(state.getCurrentUndoStage(dbTx))

	key := make([]byte, 4)
	binary.BigEndian.PutUint32(key, changeSequence)

	bucket.Put(key, serializedUndo)
	return nil
}

func (state *State) nextUndoStage(dbTx database.Tx, nextStageKey []byte) error {
	err := dbTx.Metadata().Bucket(ismStateKey).Put(undoStageKey, nextStageKey)
	if nil != err {
		return err
	}
	state.currentUndoStage = nextStageKey

	// create undo stage bucket
	dbTx.Metadata().Bucket(ismStateKey).Bucket(undoBucketKey).CreateBucket(nextStageKey)

	return nil
}

func (state *State) truncateUndos(dbTx database.Tx, currentStageKey []byte, previousStageKey []byte) error {
	if previousStageKey == nil {
		err := dbTx.Metadata().Bucket(ismStateKey).Delete(undoStageKey)
		if nil != err {
			return err
		}
	} else {
		err := dbTx.Metadata().Bucket(ismStateKey).Bucket(undoBucketKey).DeleteBucket(currentStageKey)
		if nil != err {
			return err
		}

		err = dbTx.Metadata().Bucket(ismStateKey).Put(undoStageKey, previousStageKey)
		if nil != err {
			return err
		}
	}

	state.currentUndoStage = previousStageKey

	return nil
}

func (state *State) getCurrentUndoStage(dbTx database.Tx) []byte {
	if state.currentUndoStage != nil {
		return state.currentUndoStage
	}
	state.currentUndoStage = dbTx.Metadata().Bucket(ismStateKey).Get(undoStageKey)
	return state.currentUndoStage
}

func (state *State) fetchUndos(dbTx database.Tx) ([]*undoEntry, error) {
	bucket :=
		dbTx.Metadata().Bucket(ismStateKey).Bucket(undoBucketKey).Bucket(state.getCurrentUndoStage(dbTx))

	undoEntries := []*undoEntry{}

	c := bucket.Cursor()
	// iterate from backward for undo logs
	for ok := c.Last(); ok; ok = c.Prev() {
		item := unmarshalUndo(c.Value())
		undoEntries = append(undoEntries, item)
	}

	return undoEntries, nil
}

func (state *State) InvalidateContract(contractAddress []byte) {
	if state.lStateCache != nil {
		state.lStateCache.Remove(contractAddress)
	}
}
