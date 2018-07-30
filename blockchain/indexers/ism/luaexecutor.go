// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ism

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"

	"os"

	"math/big"

	"reflect"

	"github.com/coinstack/coinstackd/blockchain/indexers/ism/sql"
	"github.com/coinstack/coinstackd/coinstack/client"
	"github.com/coinstack/coinstackd/database"
	"github.com/coinstack/coinstackd/database/ffldb"
	"github.com/coinstack/coinstackd/event"
	"github.com/btcsuite/fastsha256"
	"github.com/coinstack/gopher-lua"
	luaJson "github.com/coinstack/gopher-lua-json"
)

const (
	errMsgTxHashInvalid = "the transaction hash is invalid: "
	ExecMaxInstSize     = uint64(20000000)
	QueryMaxInstSize    = uint64(200000000)
	InvokeMaxInstSize   = uint64(20000)
)

var (
	instanceMetaKeys map[string]struct{}
	byteOrder        = binary.LittleEndian
	systemFuncs      = map[string]lua.LGFunction{
		"print":          systemPrint,
		"setItem":        setItem,
		"getItem":        getItem,
		"delItem":        delItem,
		"getSender":      getSender,
		"getCreator":     getContractID,
		"getBlockhash":   getBlockhash,
		"getTxhash":      getTxHash,
		"getConfirmed":   getConfirmed,
		"getBlockheight": getBlockHeight,
		"getTimestamp":   getTimestamp,
		"getContractID":  getContractID,
		"sha256":         sha256,
		"registEvent":    addEventListener,
		"unregistEvent":  deleteEventListener,
		"pushEvent":      pushEvent,
		"delEvent":       deleteEvent,
		"getNode":        getNode,
		"hasPermission":  hasPermission,
		"itemIterator":   newLItemIterator,
		"random":         random,
	}
)

func init() {
	instanceMetaKeys = make(map[string]struct{})
	instanceMetaKeys["body"] = struct{}{}
	instanceMetaKeys["type"] = struct{}{}
	instanceMetaKeys["hash"] = struct{}{}
}

type LuaExecutor struct {
	instanceID    []byte
	luaState      *lua.LState
	ismState      *State
	sqlState      ISQLState
	sqlTx         sql.Tx
	definition    []byte
	tx            database.Tx
	isQuery       bool
	context       *ExecutorContext
	cached        bool
	Debug         bool
	r             *rand.Rand
	NextBlockHook func()
	NextTxHook    func()
	MempoolHook   func()
}

type ExecutorContext struct {
	Sender      string
	BlockHash   string
	TxHash      string
	BlockHeight int32
	Timestamp   time.Time
	Confirmed   bool
	Node        string
}

type LuaError struct {
	Message    string `json:"error,omitempty"`
	StackTrace string `json:"stacktrace,omitempty"`
	Cause      error  `json:"cause,omitempty"`
}

func NewError(message string, stackTrace string, cause error) (err *LuaError) {
	return &LuaError{
		message,
		stackTrace,
		cause,
	}
}

func (err *LuaError) Error() string {
	return err.Message
}

func NewLState(maxInstSize uint64) *lua.LState {
	lstate := lua.NewState(lua.Options{
		SkipOpenLibs:        true,
		IncludeGoStackTrace: true,
		MaxInstSize:         maxInstSize,
	})
	for _, pair := range []struct {
		n string
		f lua.LGFunction
	}{
		{lua.LoadLibName, lua.OpenPackage}, // Must be first
		{lua.BaseLibName, lua.OpenBase},
		{lua.TabLibName, lua.OpenTable},
		{lua.StringLibName, lua.OpenString},
		{lua.MathLibName, lua.OpenMath},
	} {
		if err := lstate.CallByParam(lua.P{
			Fn:      lstate.NewFunction(pair.f),
			NRet:    0,
			Protect: true,
		}, lua.LString(pair.n)); err != nil {
			log.Critical("failed to initialize contract modules: ", err.Error())
			return nil
		}
	}
	loadLib := lstate.GetGlobal(lua.LoadLibName)
	loaders := lstate.GetField(loadLib, "loaders")
	t := loaders.(*lua.LTable)
	t.RawSetInt(2, lua.LNil)
	lstate.SetField(loadLib, "path", lua.LNil)
	lstate.SetField(loadLib, "cpath", lua.LNil)

	baseLib := lstate.GetGlobal("_G")
	lstate.SetField(baseLib, "dofile", lua.LNil)
	lstate.SetField(baseLib, "loadfile", lua.LNil)
	lstate.SetField(baseLib, "print", lua.LNil)
	lstate.SetField(baseLib, "_printregs", lua.LNil)
	lstate.SetField(baseLib, "module", lua.LNil)

	mathLib := lstate.GetGlobal(lua.MathLibName)
	lstate.SetField(mathLib, "random", lua.LNil)
	lstate.SetField(mathLib, "randomseed", lua.LNil)

	return lstate
}

func NewLuaExecutor(
	instanceID []byte,
	ismState *State,
	sqlState ISQLState,
	definition []byte,
	context *ExecutorContext,
) *LuaExecutor {
	log.Tracef("New Lua Exec %s, %#v", context.Node, *context)
	return &LuaExecutor{
		instanceID,
		nil,
		ismState,
		sqlState,
		nil,
		definition,
		nil,
		false,
		context,
		false,
		false,
		nil,
		nil,
		nil,
		nil,
	}
}

// TODO: error handling and rollback
// predefined modules for contract definition
func systemFunctionLoader(L *lua.LState) int {
	mod := L.SetFuncs(L.NewTable(), systemFuncs)
	L.Push(mod)
	return 1
}

func systemPrint(L *lua.LState) int {
	payload := L.Get(1)
	jsonValue, err := serializeValue(payload)
	if err != nil {
		L.ArgError(1, "failed to print value")
	}
	log.Debug(string(jsonValue))
	return 0
}

func debugPrint(L *lua.LState) int {
	payload := L.Get(1)
	jsonValue, err := serializeValue(payload)
	if err != nil {
		fmt.Println("failed to print value")
	}
	fmt.Println(string(jsonValue))
	return 0
}

func printErr(L *lua.LState) int {
	payload := L.Get(1)
	fmt.Fprintln(os.Stderr, payload.String())
	return 0
}

func (ex *LuaExecutor) setSender(L *lua.LState) int {
	payload := L.CheckString(1)
	ex.context.Sender = payload
	return 0
}

func (ex *LuaExecutor) nextBlock(L *lua.LState) int {
	if ex.NextBlockHook != nil {
		ex.NextBlockHook()
	}
	return 0
}

func (ex *LuaExecutor) nextTx(L *lua.LState) int {
	if ex.NextTxHook != nil {
		ex.NextTxHook()
	}
	return 0
}

func (ex *LuaExecutor) enterUnconfirmed(L *lua.LState) int {
	if ex.MempoolHook != nil {
		ex.MempoolHook()
	}
	return 0
}

func setItem(L *lua.LState) int {
	ex := getLuaExecContext(L)

	if ex.isQuery {
		L.RaiseError("can't call setItem() from Query")
	}

	key := L.CheckString(1)
	if isSystemKey(key) {
		L.ArgError(1, fmt.Sprintf("can't use the key: %v", key))
	}

	value := L.CheckAny(2)
	jsonValue, err := serializeValue(value)
	if err != nil {
		L.ArgError(2, "failed to marshal value")
	}

	L.AddInstCount(1000)

	encryptedValue := encryptValue(ex.ismState.encryptKey, jsonValue)
	err = ex.ismState.SetInstanceItem(ex.tx, ex.instanceID, []byte(key), encryptedValue)
	if err != nil {
		L.ArgError(2, fmt.Sprintf("failed to store value: %v", err))
	}
	return 0
}

func getItem(L *lua.LState) int {
	ex := getLuaExecContext(L)

	key := L.CheckString(1)
	if isSystemKey(key) {
		L.ArgError(1, fmt.Sprintf("can't use the key: %v", key))
	}

	L.AddInstCount(1000)

	var value []byte
	if ex.isQuery && !ex.ismState.EphemeralEnabled {
		if instanceBucket := ex.ismState.GetInstance(ex.tx, ex.instanceID); instanceBucket != nil {
			value = instanceBucket.Get([]byte(key))
		}
	} else {
		value = ex.ismState.GetInstanceItem(ex.tx, ex.instanceID, []byte(key))
	}
	if value == nil {
		return 0
	}

	decryptedValue := decryptValue(ex.ismState.encryptKey, value)
	item := deserializeValue(L, decryptedValue)
	L.Push(item)
	return 1
}

func delItem(L *lua.LState) int {
	ex := getLuaExecContext(L)
	if ex.isQuery || ex.ismState.EphemeralEnabled {
		L.RaiseError("can't call delItem() from Query")
	}
	key := L.CheckString(1)
	if isSystemKey(key) {
		L.ArgError(1, fmt.Sprintf("can't use the key: %v", key))
	}
	L.AddInstCount(1000)
	ex.ismState.DelInstanceItem(ex.tx, ex.instanceID, []byte(key))
	return 0
}

func getContractID(L *lua.LState) int {
	ex := getLuaExecContext(L)
	L.Push(lua.LString(ex.instanceID))
	return 1
}

func getSender(L *lua.LState) int {
	ex := getLuaExecContext(L)
	L.Push(lua.LString(ex.context.Sender))
	return 1
}

func getBlockHeight(L *lua.LState) int {
	ex := getLuaExecContext(L)
	L.Push(lua.LNumber(ex.context.BlockHeight))
	return 1
}

func getConfirmed(L *lua.LState) int {
	ex := getLuaExecContext(L)
	L.Push(lua.LBool(ex.context.Confirmed))
	return 1
}

func getBlockhash(L *lua.LState) int {
	ex := getLuaExecContext(L)
	L.Push(lua.LString(ex.context.BlockHash))
	return 1
}

func getTxHash(L *lua.LState) int {
	ex := getLuaExecContext(L)
	L.Push(lua.LString(ex.context.TxHash))
	return 1
}

func getTimestamp(L *lua.LState) int {
	ex := getLuaExecContext(L)
	L.Push(lua.LNumber(ex.context.Timestamp.Unix()))
	return 1
}

func serializeEventListener(eventType, url string) []byte {
	eventTypeByteLen := len([]byte(eventType))
	urlByteLen := len([]byte(url))
	record := make([]byte, 4+eventTypeByteLen+urlByteLen)
	offset := 0
	byteOrder.PutUint32(record[offset:], uint32(eventTypeByteLen))
	offset += 4
	copy(record[offset:], []byte(eventType))
	offset += eventTypeByteLen
	copy(record[offset:], []byte(url))
	return record
}

func deserializeEventListener(record []byte) (string, string) {
	offset := 0
	eventTypeByteLen := byteOrder.Uint32(record[offset:])
	offset += 4
	eventType := record[offset : offset+int(eventTypeByteLen)]
	offset += int(eventTypeByteLen)
	url := record[offset:]
	return string(eventType), string(url)
}

func addEventListener(L *lua.LState) int {
	ex := getLuaExecContext(L)

	eventType := L.CheckString(1)
	url := L.CheckString(2)
	node := L.CheckString(3)

	if event.AddEventListener(eventType, url, node) {
		if bucket := ex.tx.Metadata().Bucket(eventBucketKey); bucket != nil {
			record := serializeEventListener(eventType, url)
			if err := bucket.Put(record, nil); err != nil {
				L.RaiseError("failed to store EventListener: event type(%s), url(%s)",
					eventType,
					url,
				)
			}
		} else {
			log.Error("event bucket is not found")
		}
	}

	return 0
}

func deleteEventListener(L *lua.LState) int {
	ex := getLuaExecContext(L)

	eventType := L.CheckString(1)
	url := L.CheckString(2)

	event.DeleteEventListener(eventType, url)

	if bucket := ex.tx.Metadata().Bucket(eventBucketKey); bucket != nil {
		record := serializeEventListener(eventType, url)
		if err := bucket.Delete(record); err != nil {
			L.RaiseError("failed to delete EventListener: event type(%s), url(%s)",
				eventType,
				url,
			)
		}
	} else {
		log.Error("event bucket is not found")
	}

	return 0
}

func deleteEvent(L *lua.LState) int {
	ex := getLuaExecContext(L)

	eventType := L.CheckString(1)
	log.Trace("del event: ", eventType)

	delUrls := event.DeleteEvent(eventType)

	if bucket := ex.tx.Metadata().Bucket(eventBucketKey); bucket != nil {
		for _, url := range delUrls {
			record := serializeEventListener(eventType, url)
			if err := bucket.Delete(record); err != nil {
				L.RaiseError("failed to delete Event: event type(%s)",
					eventType,
				)
			}
		}
	} else {
		log.Error("event bucket is not found")
	}

	return 0
}

func pushEvent(L *lua.LState) int {
	eventType := L.CheckString(1)
	value := L.CheckAny(2)
	jsonValue, err := serializeValue(value)
	if err != nil {
		L.ArgError(2, "failed to marshal value")
		return 0
	}
	rawValue := json.RawMessage(jsonValue)
	log.Trace("pushEvent: ", value.String())
	event.PushEvent(eventType, &rawValue)
	return 0
}

func getNode(L *lua.LState) int {
	ex := getLuaExecContext(L)
	value := ex.context.Node
	log.Trace("getNode: ", value)
	L.Push(lua.LString(value))
	return 1
}

func sha256(L *lua.LState) int {
	key := L.CheckString(1)
	payload := []byte(key)
	hasher := fastsha256.New()
	hasher.Write(payload)
	hashed := hex.EncodeToString(hasher.Sum(nil))
	L.Push(lua.LString(hashed))
	return 1
}

const PermPrefix = "__ACCESS_"

func makeGrantAccessKey(address, token string) []byte {
	return []byte(PermPrefix + address + "_" + token)
}

func (ex *LuaExecutor) grantAccess(L *lua.LState) int {
	if string(ex.instanceID) != ex.context.Sender {
		L.RaiseError("insufficient privileges: can't grant")
	}
	address := L.CheckString(1)
	token := L.CheckString(2)
	key := makeGrantAccessKey(address, token)
	err := ex.ismState.SetInstanceItem(ex.tx, ex.instanceID, key, []byte("1"))
	if err != nil {
		L.ArgError(2, fmt.Sprintf("failed to store token: %v", err))
	}
	return 0
}

func (ex *LuaExecutor) revokeAccess(L *lua.LState) int {
	if string(ex.instanceID) != ex.context.Sender {
		L.RaiseError("insufficient privileges: can't revoke")
	}
	address := L.CheckString(1)
	token := L.CheckString(2)
	key := makeGrantAccessKey(address, token)
	err := ex.ismState.SetInstanceItem(ex.tx, ex.instanceID, key, []byte("0"))
	if err != nil {
		L.ArgError(2, fmt.Sprintf("failed to store token: %v", err))
	}
	return 0
}

func hasPermission(L *lua.LState) int {
	ex := getLuaExecContext(L)
	if string(ex.instanceID) == ex.context.Sender {
		log.Trace("system.hasPermission - owner")
		L.Push(lua.LTrue)
		return 1
	}

	token := L.CheckString(1)
	key := makeGrantAccessKey(ex.context.Sender, token)
	var value []byte
	if ex.isQuery {
		if instanceBucket := ex.ismState.GetInstance(ex.tx, ex.instanceID); instanceBucket != nil {
			value = instanceBucket.Get([]byte(key))
		}
	} else {
		value = ex.ismState.GetInstanceItem(ex.tx, ex.instanceID, key)
	}
	if value == nil {
		L.Push(lua.LFalse)
		return 1
	}
	if string(value) == "0" {
		L.Push(lua.LFalse)
		return 1
	}

	L.Push(lua.LTrue)
	return 1
}

type skipFunc func(key string) bool

type ItemIterator struct {
	keyCursor      database.Cursor
	dbCursor       database.Cursor
	curCursor      database.Cursor
	keyCursorValid bool
	dbCursorValid  bool
	isNew          bool
	keys           database.Bucket
	remove         database.Bucket
	encryptKey     []byte
	skip           skipFunc
}

const lItemIteratorName = "LItemIterator"

func registerLItemIteratorType(L *lua.LState) {
	mt := L.NewTypeMetatable(lItemIteratorName)
	L.SetGlobal("ItemIterator", mt)
	// static attributes
	L.SetField(mt, "new", L.NewFunction(newLItemIterator))
	// methods
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), lItemIteratorMethods))
}

func getLuaExecContext(L *lua.LState) *LuaExecutor {
	val := L.GetGlobal(luaExecContext)
	ud, ok := val.(*lua.LUserData)
	if !ok {
		L.RaiseError("lua runtime executor is nil")
	}
	ex, ok := ud.Value.(*LuaExecutor)
	if !ok {
		L.RaiseError("lua runtime executor is invalid")
	}
	return ex
}

func newLItemIterator(L *lua.LState) int {
	prefix := L.OptString(1, "")
	ex := getLuaExecContext(L)
	if ex.ismState.EphemeralEnabled {
		L.RaiseError("can not use ItemIterator on ephemeral mode")
	}
	iter := NewItemIterator(ex, prefix)
	if iter == nil {
		L.RaiseError("can't create a ItemIterator: item bucket is not initialized")
	}
	ud := L.NewUserData()
	ud.Value = iter
	L.SetMetatable(ud, L.GetTypeMetatable(lItemIteratorName))
	L.Push(ud)
	return 1
}

func checkLItemIterator(L *lua.LState) *ItemIterator {
	ud := L.CheckUserData(1)
	if v, ok := ud.Value.(*ItemIterator); ok {
		return v
	}
	L.ArgError(1, "ItemIterator expected")
	return nil
}

var lItemIteratorMethods = map[string]lua.LGFunction{
	"next":  lItemIteratorNext,
	"key":   lItemIteratorKey,
	"value": lItemIteratorValue,
}

func lItemIteratorNext(L *lua.LState) int {
	iter := checkLItemIterator(L)
	if iter.Next() {
		L.Push(lua.LTrue)
	} else {
		L.Push(lua.LFalse)
	}
	return 1
}

func lItemIteratorKey(L *lua.LState) int {
	iter := checkLItemIterator(L)
	key := iter.Key()
	if key != nil {
		L.Push(lua.LString(string(key)))
	} else {
		L.Push(lua.LNil)
	}
	return 1
}

func lItemIteratorValue(L *lua.LState) int {
	iter := checkLItemIterator(L)
	value := iter.Value()
	if value != nil {
		L.Push(deserializeValue(L, value))
	} else {
		L.Push(lua.LNil)
	}
	return 1
}

func NewItemIterator(exec *LuaExecutor, prefix string) *ItemIterator {
	instance := exec.ismState.GetInstance(exec.tx, exec.instanceID)
	if instance == nil {
		return nil
	}
	var keyCursor database.Cursor
	var keys database.Bucket
	var remove database.Bucket
	if batch, ok := exec.ismState.batch[string(exec.instanceID)]; ok && !exec.isQuery {
		keys = batch[IsmBatchKeys]
		remove = batch[IsmBatchRemove]
		keyCursor = keys.RangeCursor([]byte(prefix))
	} else {
		keys = ffldb.NewTreapBucket()
		remove = ffldb.NewTreapBucket()
		keyCursor = keys.Cursor()
	}
	iter := &ItemIterator{
		keyCursor,
		instance.RangeCursor([]byte(prefix)),
		nil,
		false,
		false,
		true,
		keys,
		remove,
		exec.ismState.encryptKey,
		isSystemKey,
	}
	return iter
}

func NewPermissionIterator(ismState *State, dbTx database.Tx, instanceID string) *ItemIterator {
	instance := ismState.GetInstance(dbTx, []byte(instanceID))
	if instance == nil {
		return nil
	}
	keys := ffldb.NewTreapBucket()
	remove := ffldb.NewTreapBucket()
	keyCursor := keys.Cursor()

	iter := &ItemIterator{
		keyCursor,
		instance.RangeCursor([]byte(PermPrefix)),
		nil,
		false,
		false,
		true,
		keys,
		remove,
		ismState.encryptKey,
		isInstanceMetaKey,
	}
	return iter
}

func (iter *ItemIterator) first() bool {
	iter.keyCursorValid = iter.keyCursor.First()
	iter.dbCursorValid = iter.dbCursor.First()
	return iter.chooseIterator()
}

func (iter *ItemIterator) chooseIterator() bool {
	iter.skipItemUpdates()

	if !iter.dbCursorValid && !iter.keyCursorValid {
		iter.curCursor = nil
		return false
	}

	if !iter.keyCursorValid {
		iter.curCursor = iter.dbCursor
		return true
	}

	if !iter.dbCursorValid {
		iter.curCursor = iter.keyCursor
		return true
	}

	compare := bytes.Compare(iter.dbCursor.Key(), iter.keyCursor.Key())
	if compare > 0 {
		iter.curCursor = iter.keyCursor
	} else {
		iter.curCursor = iter.dbCursor
	}
	return true
}

func random(L *lua.LState) int {
	ex := getLuaExecContext(L)
	switch L.GetTop() {
	case 0:
		L.Push(lua.LNumber(ex.r.Float64()))
	case 1:
		n := L.CheckInt(1)
		L.Push(lua.LNumber(ex.r.Intn(n-1) + 1))
	default:
		min := L.CheckInt(1)
		max := L.CheckInt(2) + 1
		L.Push(lua.LNumber(ex.r.Intn(max-min) + min))
	}
	return 1
}

func isSystemKey(key string) bool {
	if isInstanceMetaKey(key) {
		return true
	} else if strings.HasPrefix(key, PermPrefix) {
		return true
	} else {
		return false
	}
}

func isInstanceMetaKey(key string) bool {
	_, ok := instanceMetaKeys[key]
	return ok
}

func (iter *ItemIterator) skipItemUpdates() {
	for iter.dbCursorValid {
		var skip bool
		key := iter.dbCursor.Key()
		if iter.remove.Get(key) != nil {
			skip = true
		} else if iter.keys.Get(key) != nil {
			skip = true
		} else if iter.skip(string(key)) {
			skip = true
		}
		if !skip {
			break
		}
		iter.dbCursorValid = iter.dbCursor.Next()
	}
	for iter.keyCursorValid {
		key := iter.keyCursor.Key()
		if !iter.skip(string(key)) {
			break
		}
		iter.keyCursorValid = iter.keyCursor.Next()
	}
}

func (iter *ItemIterator) Next() bool {
	if iter.isNew {
		iter.isNew = false
		return iter.first()
	}
	if iter.curCursor == nil {
		return false
	}
	if iter.curCursor == iter.keyCursor {
		iter.keyCursorValid = iter.keyCursor.Next()
	} else {
		iter.dbCursorValid = iter.dbCursor.Next()
	}
	return iter.chooseIterator()
}

func (iter *ItemIterator) Key() []byte {
	if iter.curCursor == nil {
		return nil
	}
	return iter.curCursor.Key()
}

func (iter *ItemIterator) Value() []byte {
	if iter.curCursor == nil {
		return nil
	}
	return decryptValue(iter.encryptKey, iter.curCursor.Value())
}

func (ex *LuaExecutor) call(L *lua.LState) int {
	ex.callByParam(L, 1)

	ret := ex.luaState.Get(-1) // returned value
	ex.luaState.Pop(1)         // remove received value
	L.Push(ret)
	L.Push(lua.LBool(true)) // always true: deprecated
	return 2
}

func (ex *LuaExecutor) invoke(L *lua.LState) int {
	ex.callByParam(L, lua.MultRet)

	var returnValue lua.LValue
	switch nReturnValue := ex.luaState.GetTop(); nReturnValue {
	case 0:
		return 0
	case 1:
		returnValue = ex.luaState.Get(-1)
		ex.luaState.Pop(1)
		L.Push(returnValue)
		return 1
	default:
		for i := 1; i <= nReturnValue; i++ {
			returnValue := ex.luaState.Get(i)
			L.Push(returnValue)
		}
		ex.luaState.Pop(nReturnValue)
		return nReturnValue
	}
}

func (ex *LuaExecutor) callByParam(L *lua.LState, nRet int) {
	numArgs := L.GetTop()
	if numArgs < 1 {
		L.RaiseError("not enough arguments")
	}

	fnName := L.CheckString(1)
	fn := ex.luaState.GetGlobal(fnName)
	if fn == lua.LNil {
		L.ArgError(1, fmt.Sprintf("method %s not found", fnName))
	}

	log.Tracef("calling: %v, num arguments: %v", fnName, numArgs-1)

	var args []lua.LValue
	if numArgs > 1 {
		args = make([]lua.LValue, numArgs-1)
		for i := 2; i <= numArgs; i++ {
			// TODO: filter arg type e.g. exclude table, function
			args[i-2] = L.Get(i)
		}
	}

	ex.luaState.CallByParam(lua.P{
		Fn:      fn,
		NRet:    nRet,
		Protect: false,
	}, args...)

	log.Trace("called function: ", fnName)
}

const luaExecContext = "__exec_context__"

func setLuaExecContext(L *lua.LState, exec *LuaExecutor) {
	ud := L.NewUserData()
	ud.Value = exec
	L.SetGlobal(luaExecContext, ud)
}

func (ex *LuaExecutor) Init(dbTx database.Tx) error {
	if ex.ismState.lStateCache == nil {
		return ex.newLState(ExecMaxInstSize)
	}
	ex.cached = true
	L, _ := ex.ismState.lStateCache.Get(ex.instanceID)
	if L != nil {
		ex.luaState = L
		return ex.setLuaRuntimeContext()
	}

	// initialize execution context
	err := ex.newLState(ExecMaxInstSize)
	if err != nil {
		return err
	}

	ex.ismState.lStateCache.Put(ex.instanceID, ex.luaState)

	return nil
}

func (ex *LuaExecutor) preloadModule() {
	preloadSystem(ex.luaState)
	preloadLuaJSON(ex.luaState)
	preloadDB(ex.luaState)
	registerLItemIteratorType(ex.luaState)
	registerLDBResultSetType(ex.luaState)
	registerLDBSqlStmtType(ex.luaState)
}

func (ex *LuaExecutor) setLuaRuntimeContext() error {
	var randSrc rand.Source
	l := len(ex.context.TxHash)
	switch {
	case l == 0:
		randSrc = rand.NewSource(ex.context.Timestamp.Unix())
	case l == 64:
		n := big.Int{}
		x, _ := n.SetString(ex.context.TxHash[:7], 16)
		if x == nil {
			return errors.New(errMsgTxHashInvalid + ex.context.TxHash)
		}
		randSrc = rand.NewSource(x.Int64())
	default:
		return errors.New(errMsgTxHashInvalid + ex.context.TxHash)
	}
	ex.r = rand.New(randSrc)
	setLuaExecContext(ex.luaState, ex)
	return nil
}

func (ex *LuaExecutor) newLState(maxInstSize uint64) error {
	// initialize execution context
	ex.luaState = NewLState(maxInstSize)
	if ex.luaState == nil {
		return errors.New("failed to create lua state")
	}

	ex.preloadModule()
	err := ex.setLuaRuntimeContext()
	if err != nil {
		log.Error("fail to initialize sc executor: ", err.Error())
		return err
	}

	// execute definition
	err = ex.luaState.DoString(string(ex.definition))
	if err != nil {
		log.Error("fail to initialize sc executor: ", err.Error())
		return err
	}

	return nil
}

func (ex *LuaExecutor) debugFunctionLoader(L *lua.LState) int {
	var exports = map[string]lua.LGFunction{
		"print":          debugPrint,
		"printErr":       printErr,
		"setSender":      ex.setSender,
		"nextBlock":      ex.nextBlock,
		"nextTx":         ex.nextTx,
		"setUnconfirmed": ex.enterUnconfirmed,
	}
	// register functions to the table
	mod := L.SetFuncs(L.NewTable(), exports)

	// returns the module
	L.Push(mod)
	return 1
}

func (ex *LuaExecutor) Execute(dbTx database.Tx, execution []byte) error {
	exStartTime := time.Now()
	defer func() {
		ex.ismState.Stat.Exec.Run.AddDelta(exStartTime)
	}()

	state := NewLState(InvokeMaxInstSize)
	if state == nil {
		return errors.New("failed to initialize contract modules")
	}
	defer state.Close()

	preloadLuaJSON(state)
	state.SetGlobal("call", state.NewFunction(ex.call))
	state.SetGlobal("invoke", state.NewFunction(ex.invoke))
	state.SetGlobal("grant", state.NewFunction(ex.grantAccess))
	state.SetGlobal("revoke", state.NewFunction(ex.revokeAccess))
	if ex.Debug {
		state.PreloadModule("system", ex.debugFunctionLoader)
	}

	log.Trace("execution: ", string(execution))

	// invoke execution command
	ex.tx = dbTx
	sqlTx, err := ex.sqlState.Tx(string(ex.instanceID))
	if err != nil {
		panic(err)
	}
	err = sqlTx.Savepoint()
	if err != nil {
		panic(err)
	}
	ex.sqlTx = sqlTx

	err = state.DoString(string(execution))
	if err != nil {
		log.Error("failed to execute: ", err.Error())
		ex.ismState.Rollback(dbTx, ex.instanceID)
		if err2 := ex.sqlTx.RollbackToSavepoint(); err2 != nil {
			panic(err)
		}
		if ex.ismState.lStateCache != nil {
			ex.ismState.lStateCache.Remove(ex.instanceID)
		}
		return err
	}

	commitStartTime := time.Now()
	ex.ismState.Commit(dbTx, ex.instanceID)
	err = ex.sqlTx.Release()
	if err != nil {
		panic(err)
	}
	ex.ismState.Stat.Exec.Commit.AddDelta(commitStartTime)
	return nil
}

func (ex *LuaExecutor) Query(dbTx database.Tx, execution []byte) ([]byte, error) {
	queryInitTime := time.Now()
	err := ex.newLState(QueryMaxInstSize)
	if err != nil {
		return nil, errors.New("failed to initialize contract modules")
	}
	ex.ismState.Stat.Query.Init.AddDelta(queryInitTime)
	defer ex.Finish()

	queryStartTime := time.Now()
	defer func() {
		ex.ismState.Stat.Query.Run.AddDelta(queryStartTime)
	}()
	state := NewLState(InvokeMaxInstSize)
	if state == nil {
		return nil, errors.New("failed to initialize contract modules")
	}
	defer state.Close()

	preloadLuaJSON(state)
	state.SetGlobal("call", state.NewFunction(ex.call))
	state.SetGlobal("invoke", state.NewFunction(ex.invoke))

	log.Trace("query: ", string(execution))

	// invoke execution command
	top := state.GetTop()
	ex.tx = dbTx
	ex.isQuery = true
	sqlTx, err := ex.sqlState.ReadOnlyTx(string(ex.instanceID))
	if err != nil {
		return nil, err
	}
	ex.sqlTx = sqlTx
	defer sqlTx.Rollback()

	err = state.DoString(string(execution))
	if err != nil {
		log.Error("failed to query: ", err.Error())
		luaError, ok := err.(*lua.ApiError)
		if !ok {
			return nil, err
		}
		return nil, NewError(luaError.Object.String(), luaError.StackTrace, luaError.Cause)
	}

	var returnValue lua.LValue
	switch nReturnValue := state.GetTop() - top; nReturnValue {
	case 0:
		returnValue = nil
	case 1:
		returnValue = state.Get(-1)
	default:
		results := state.NewTable()
		for i := 1; i <= nReturnValue; i++ {
			results.RawSetInt(i, state.Get(i))
		}
		returnValue = results
	}

	if returnValue == nil {
		return nil, nil
	}

	jsonValue, err := serializeValue(returnValue)
	if err != nil {
		return nil, err
	}

	return jsonValue, nil
}

func (ex *LuaExecutor) Finish() {
	if !ex.cached {
		ex.luaState.Close()
	}
}

func newFnArgs(locals []*lua.DbgLocalInfo, nargs uint8) client.ContractFnArgs {
	fnArgs := make(client.ContractFnArgs, 0)
	for i, v := range locals {
		if i == int(nargs) {
			break
		}
		fnArgs = append(fnArgs, v.Name)
	}
	return fnArgs
}

type SrcPosSorter []*client.ContractFnSig

func (s SrcPosSorter) Len() int {
	return len(s)
}

func (s SrcPosSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s SrcPosSorter) Less(i, j int) bool {
	return s[i].SrcPos < s[j].SrcPos
}

func (ex *LuaExecutor) FnSigs(dbTx database.Tx) ([]*client.ContractFnSig, error) {
	err := ex.newLState(uint64(0))
	if err != nil {
		return nil, err
	}
	defer ex.Finish()
	defer ex.ismState.Rollback(dbTx, ex.instanceID)

	gEnv := ex.luaState.Env
	if gEnv == nil {
		return nil, errors.New("failed to initialize contract modules")
	}
	fnSigs := make(SrcPosSorter, 0)
	gEnv.ForEach(func(k, v lua.LValue) {
		if v.Type() == lua.LTFunction {
			f := v.(*lua.LFunction)
			if f.Proto != nil {
				fnSigs = append(
					fnSigs,
					&client.ContractFnSig{
						Name:     k.String(),
						Args:     newFnArgs(f.Proto.DbgLocals, f.Proto.NumParameters),
						Variadic: f.Proto.IsVarArg != 0,
						SrcPos:   f.Proto.LineDefined,
					},
				)
			}
		}
	})
	sort.Sort(fnSigs)

	return fnSigs, nil
}

func (ex *LuaExecutor) GlobalEnv() *lua.LTable {
	if ex == nil || ex.luaState == nil {
		return nil
	}
	return ex.luaState.Env
}

func preloadSystem(L *lua.LState) {
	L.PreloadModule("system", systemFunctionLoader)
}

// used by cmd/contractctl
func ReplaceDebugPrint() {
	systemFuncs["print"] = debugPrint
}

func preloadLuaJSON(L *lua.LState) {
	L.PreloadModule("json", luaJSONLoader)
}

func luaJSONLoader(L *lua.LState) int {
	t := L.NewTable()
	L.SetFuncs(t, luaJSONApi)
	L.Push(t)
	return 1
}

var luaJSONApi = map[string]lua.LGFunction{
	"decode": luaJSONDecode,
	"encode": luaJSONEncode,
}

func luaJSONDecode(L *lua.LState) int {
	str := L.CheckString(1)
	var value interface{}
	err := json.Unmarshal([]byte(str), &value)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(luaJson.FromJSON(L, value))
	return 1
}

func luaJSONEncode(L *lua.LState) int {
	value := L.CheckAny(1)

	jv := luaJson.NewJsonValue(value)
	data, err := jv.MarshalJSON()
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}
	L.Push(lua.LString(string(data)))
	return 1
}

func serializeValue(value lua.LValue) ([]byte, error) {
	jsonValue := luaJson.NewJsonValue(value)
	return jsonValue.MarshalJSON()
}

func deserializeValue(L *lua.LState, value []byte) lua.LValue {
	var parsedJSON interface{}
	json.Unmarshal(value, &parsedJSON)
	return luaJson.FromJSON(L, parsedJSON)
}

func preloadDB(L *lua.LState) {
	L.PreloadModule("db", dbLoader)
}

func dbLoader(L *lua.LState) int {
	t := L.NewTable()
	L.SetFuncs(t, dbFuncs)
	L.Push(t)
	return 1
}

var dbFuncs = map[string]lua.LGFunction{
	"exec":    dbExec,
	"query":   dbQuery,
	"prepare": dbPrepare,
}

func buildArgs(L *lua.LState, startIdx int) []interface{} {
	n := L.GetTop()
	args := make([]interface{}, n-(startIdx-1))
	for i := startIdx; i <= n; i++ {
		v := L.CheckAny(i)
		switch v.(type) {
		case lua.LString:
			args[i-startIdx] = lua.LVAsString(v)
		case lua.LBool:
			args[i-startIdx] = lua.LVAsBool(v)
		case lua.LNumber:
			n := lua.LVAsNumber(v)
			if float64(n) == float64(int64(n)) {
				args[i-startIdx] = int64(n)
			} else {
				args[i-startIdx] = float64(n)
			}
		default:
			L.TypeError(i, v.Type())
		}
	}
	return args
}

func dbExec(L *lua.LState) int {
	ex := getLuaExecContext(L)
	query := L.CheckString(1)
	args := buildArgs(L, 2)
	L.AddInstCount(100000)
	if err := ex.sqlTx.Exec(query, args...); err != nil {
		L.RaiseError(err.Error())
	}
	return 0
}

func dbQuery(L *lua.LState) int {
	ex := getLuaExecContext(L)
	query := L.CheckString(1)
	args := buildArgs(L, 2)
	L.AddInstCount(100000)
	rows, err := ex.sqlTx.Query(query, args...)
	if err != nil {
		L.RaiseError(err.Error())
	}
	cols, err := rows.Columns()
	if err != nil {
		L.RaiseError(err.Error())
	}
	vals := make([]interface{}, len(cols))
	valPtrs := make([]interface{}, len(cols))
	for i := 0; i < len(cols); i++ {
		valPtrs[i] = &vals[i]
	}
	ud := L.NewUserData()
	ud.Value = &lDBResultSet{
		Rows:    rows,
		vals:    vals,
		valPtrs: valPtrs,
	}
	L.SetMetatable(ud, L.GetTypeMetatable(lDBResultSetName))
	L.Push(ud)
	return 1
}

func dbPrepare(L *lua.LState) int {
	ex := getLuaExecContext(L)
	query := L.CheckString(1)
	stmt, err := ex.sqlTx.Prepare(query)
	if err != nil {
		L.RaiseError(err.Error())
	}
	ud := L.NewUserData()
	ud.Value = stmt
	L.SetMetatable(ud, L.GetTypeMetatable(lDBSqlStmtName))
	L.Push(ud)
	return 1
}

const lDBSqlStmtName = "DBSqlStmt"

func registerLDBSqlStmtType(L *lua.LState) {
	mt := L.NewTypeMetatable(lDBSqlStmtName)
	L.SetGlobal(lDBSqlStmtName, mt)
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), lDBSqlStmtMethods))
}

func checkLDBSqlStmt(L *lua.LState) sql.Stmt {
	ud := L.CheckUserData(1)
	if v, ok := ud.Value.(sql.Stmt); ok {
		return v
	}
	L.ArgError(1, "SqlStmt expected")
	return nil
}

var lDBSqlStmtMethods = map[string]lua.LGFunction{
	"exec":  dbSqlStmtExec,
	"query": dbSqlStmtQuery,
}

func dbSqlStmtExec(L *lua.LState) int {
	stmt := checkLDBSqlStmt(L)
	args := buildArgs(L, 2)
	L.AddInstCount(100000)
	err := stmt.Exec(args...)
	if err != nil {
		L.RaiseError(err.Error())
	}
	return 0
}

func dbSqlStmtQuery(L *lua.LState) int {
	stmt := checkLDBSqlStmt(L)
	args := buildArgs(L, 2)
	L.AddInstCount(100000)
	rows, err := stmt.Query(args...)
	if err != nil {
		L.RaiseError(err.Error())
	}
	cols, err := rows.Columns()
	if err != nil {
		L.RaiseError(err.Error())
	}
	vals := make([]interface{}, len(cols))
	valPtrs := make([]interface{}, len(cols))
	for i := 0; i < len(cols); i++ {
		valPtrs[i] = &vals[i]
	}
	ud := L.NewUserData()
	ud.Value = &lDBResultSet{
		Rows:    rows,
		vals:    vals,
		valPtrs: valPtrs,
	}
	L.SetMetatable(ud, L.GetTypeMetatable(lDBResultSetName))
	L.Push(ud)
	return 1
}

const lDBResultSetName = "DBResultSet"

type lDBResultSet struct {
	*sql.Rows
	vals    []interface{}
	valPtrs []interface{}
}

func registerLDBResultSetType(L *lua.LState) {
	mt := L.NewTypeMetatable(lDBResultSetName)
	L.SetGlobal(lDBResultSetName, mt)
	L.SetField(mt, "__index", L.SetFuncs(L.NewTable(), lDBResultSetMethods))
}

func checkLDBResultSet(L *lua.LState) *lDBResultSet {
	ud := L.CheckUserData(1)
	if v, ok := ud.Value.(*lDBResultSet); ok {
		return v
	}
	L.ArgError(1, "ResultSet expected")
	return nil
}

var lDBResultSetMethods = map[string]lua.LGFunction{
	"next": dbResultSetNext,
	"get":  dbResultSetGet,
}

func dbResultSetNext(L *lua.LState) int {
	rs := checkLDBResultSet(L)
	L.Push(lua.LBool(rs.Next()))
	return 1
}

func dbResultSetGet(L *lua.LState) int {
	L.AddInstCount(10)
	rs := checkLDBResultSet(L)
	err := rs.Scan(rs.valPtrs...)
	if err != nil {
		L.RaiseError(err.Error())
	}
	for _, val := range rs.vals {
		if val != nil {
			switch v := val.(type) {
			case int64:
				L.Push(lua.LNumber(v))
			case float64:
				L.Push(lua.LNumber(v))
			case string:
				L.Push(lua.LString(v))
			case []uint8:
				L.Push(lua.LString(string(v)))
			case time.Time:
				L.Push(lua.LString(v.Format(time.RFC3339Nano)))
			default:
				L.RaiseError("unsupported data type: %s", reflect.TypeOf(v).String())
			}
		} else {
			L.Push(lua.LNil)
		}
	}
	return len(rs.valPtrs)
}
