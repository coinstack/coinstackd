// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ism

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"time"

	"bytes"

	"strings"

	"github.com/coinstack/coinstackd/blockchain/indexers/ism/sql"
	"github.com/coinstack/coinstackd/database"
	"github.com/btcsuite/btclog"
	"github.com/coinstack/gopher-lua"
	luaJson "github.com/coinstack/gopher-lua-json"
)

const (
	defaultUser     = "contract"
	defaultContract = "contract"
)

func init() {
	backendLogger := btclog.NewDefaultBackendLogger()
	_ = btclog.NewSubsystemLogger(backendLogger, "")
	UseLogger(btclog.NewSubsystemLogger(backendLogger, "TEST-ISM: "))
}

type blockChain struct {
	path     string
	kv       database.DB
	ismState *State
	sqlState *SQLState
	t        *testing.T
	no       int
}

func loadBlockChain(t *testing.T) *blockChain {
	dbPath := filepath.Join(os.TempDir(), "test-ismindex")
	_ = os.RemoveAll(dbPath)
	idb, err := database.Create(ismDbType, dbPath, ismBlockDataNet)
	if err != nil {
		t.Errorf("failed to create test database (%s) %v", ismDbType, err)
	}
	err = sql.LoadTestDatabase(dbPath)
	if err != nil {
		t.Errorf("failed to create test database (%s) %v", "sqldb", err)
	}
	ismState := NewState()
	sqlState := NewSQLState(ismState)
	err = idb.Update(func(tx database.Tx) error {
		ismState.Create(tx)
		sqlState.Init(tx)
		return nil
	})
	if err != nil {
		t.Errorf("failed to load database: %v", err)
	}
	return &blockChain{
		path:     dbPath,
		kv:       idb,
		ismState: ismState,
		sqlState: sqlState,
		t:        t,
		no:       0,
	}
}

func (db *blockChain) connectBlock(
	luaTxs ...luaTx,
) {
	db.no++
	blockHash := fmt.Sprintf("BLOCK[%d]", db.no)
	err := db.kv.Update(func(tx database.Tx) error {
		db.ismState.NewStage(tx, []byte(blockHash))
		db.sqlState.NewStage(tx)
		for _, luaTx := range luaTxs {
			err := luaTx.run(tx, blockHash, db.ismState, db.sqlState)
			if err != nil {
				db.t.Error(err)
			}
		}
		return db.sqlState.CloseStage(tx)
	})
	if err != nil {
		db.t.Error(err)
	}
}

func (db *blockChain) disconnectBlock() {
	blockHash := fmt.Sprintf("BLOCK[%d]", db.no)
	db.no--
	prevBlockHash := fmt.Sprintf("BLOCK[%d]", db.no)
	err := db.kv.Update(func(tx database.Tx) error {
		err := db.ismState.UndoStage(tx, []byte(blockHash), []byte(prevBlockHash))
		if err != nil {
			return err
		}
		return db.sqlState.UndoStage(tx)
	})
	if err != nil {
		db.t.Error(err)
	}
}

func (db *blockChain) view(
	queries ...*luaQuery,
) {
	blockHash := fmt.Sprintf("BLOCK[%d]", db.no)
	db.kv.View(func(tx database.Tx) error {
		for _, query := range queries {
			err := query.query(tx, blockHash, db.ismState, db.sqlState)
			if err != nil {
				db.t.Error(err)
			}
		}
		return nil
	})
}

func (db *blockChain) cleanup() {
	sql.Close()
	db.kv.Close()
	os.RemoveAll(db.path)
}

type luaTx interface {
	run(tx database.Tx, blockHash string, ismState *State, sqlState *SQLState) error
}

type luaTxCommon struct {
	sender    string
	timestamp time.Time
	instance  string
	def       string
	cmd       string
}

type luaTxDef struct {
	luaTxCommon
}

func newLuaTxDef(instance string) *luaTxDef {
	return &luaTxDef{
		luaTxCommon{
			"",
			time.Now(),
			instance,
			"",
			"",
		},
	}
}

func (l *luaTxDef) run(tx database.Tx, blockHash string, ismState *State, sqlState *SQLState) error {
	ismState.CreateInstanceIfNotExist(tx, []byte(l.instance))
	return nil
}

type luaTxEx struct {
	luaTxCommon
}

type luaTxExFail struct {
	luaTxCommon
	expected string
}

func newLuaTxEx(sender, instance, def, cmd string) *luaTxEx {
	return &luaTxEx{
		luaTxCommon{
			sender,
			time.Now(),
			instance,
			def,
			cmd,
		},
	}
}

func (l *luaTxEx) run(tx database.Tx, blockHash string, ismState *State, sqlState *SQLState) error {
	e := newLuaTestExecutor(tx, blockHash, l.sender, l.instance, l.timestamp, l.def, ismState, sqlState)
	e.E([]byte(l.cmd))
	return e.err
}

func newLuaTxExFail(sender, instance, def, cmd, expected string) *luaTxExFail {
	return &luaTxExFail{
		luaTxCommon: luaTxCommon{
			sender,
			time.Now(),
			instance,
			def,
			cmd,
		},
		expected: expected,
	}
}

func (l *luaTxExFail) run(tx database.Tx, blockHash string, ismState *State, sqlState *SQLState) error {
	e := newLuaTestExecutor(tx, blockHash, l.sender, l.instance, l.timestamp, l.def, ismState, sqlState)
	e.E([]byte(l.cmd))
	if e.err == nil {
		return fmt.Errorf("query error: expected - %s, but got - %s", l.expected, "")
	} else {
		errStr := e.err.Error()
		if !strings.Contains(errStr, l.expected) {
			return fmt.Errorf("query error: expected - %s, but got - %s", l.expected, errStr)
		}
	}
	return nil
}

type luaQuery struct {
	luaTxCommon
	expected []byte
}

func newLuaQuery(sender, instance, def, cmd, expected string) *luaQuery {
	return &luaQuery{
		luaTxCommon{
			sender,
			time.Now(),
			instance,
			def,
			cmd,
		},
		[]byte(expected),
	}
}

func (l *luaQuery) query(tx database.Tx, blockHash string, ismState *State, sqlState *SQLState) error {
	e := newLuaTestExecutor(tx, blockHash, l.sender, l.instance, l.timestamp, l.def, ismState, sqlState)
	e.Q([]byte(l.cmd), l.expected)
	return e.err
}

type LuaTestExecutor struct {
	exec *LuaExecutor
	tx   database.Tx
	err  error
}

func newLuaTestExecutor(
	tx database.Tx,
	blockHash string,
	sender string,
	instance string,
	timestamp time.Time,
	luaDef string,
	ismState *State,
	sqlState *SQLState,
) *LuaTestExecutor {
	exec := &LuaTestExecutor{
		exec: NewLuaExecutor(
			[]byte(instance),
			ismState,
			sqlState,
			[]byte(luaDef),
			&ExecutorContext{
				Sender:    sender,
				BlockHash: blockHash,
				Timestamp: timestamp,
			},
		),
		tx: tx,
	}
	exec.I()
	return exec
}

func (e *LuaTestExecutor) I() {
	if e.err == nil {
		e.err = e.exec.Init(e.tx)
	}
}

func (e *LuaTestExecutor) E(code []byte) {
	if e.err == nil {
		e.err = e.exec.Execute(e.tx, code)
	}
}

func (e *LuaTestExecutor) Q(code, expected []byte) {
	if e.err == nil {
		var result []byte
		result, e.err = e.exec.Query(e.tx, code)
		if e.err == nil {
			if len(expected) > 0 && bytes.Compare(result, expected) != 0 {
				e.err = fmt.Errorf("query error: expected - %s, but got - %s",
					string(expected), string(result))
			}
		}
	}
}

func TestLuaExecutor(t *testing.T) {
	log.SetLevel(btclog.DebugLvl)

	bc := loadBlockChain(t)
	defer bc.cleanup()

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			`
local system = require("system")
function foo(msg)
  return msg
end
function log(msg)
  system.print(msg)
end`,
			`local foo = call("foo", "hello world from invoker"); call("log", foo);`,
		),
	)
}

func TestLuaQuery(t *testing.T) {
	log.SetLevel(btclog.DebugLvl)

	bc := loadBlockChain(t)
	defer bc.cleanup()

	def := `
local system = require("system")
function foo()
  return {1,2,3}
end
function foo2(bar)
  return bar
end`

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			def,
			`res, ok = call("foo2", call("foo")); return res;`,
			`[1,2,3]`,
		),
		newLuaQuery(
			defaultUser,
			defaultContract,
			def,
			`return "foo314"`,
			`"foo314"`,
		),
	)
}

func TestLuaContext(t *testing.T) {
	log.SetLevel(btclog.DebugLvl)

	bc := loadBlockChain(t)
	defer bc.cleanup()

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			`
local system = require("system")
function foo(msg)
  system.print(system.getContractID())
  system.print(system.getSender())
  system.print(system.getBlockhash())
  system.print(system.getTimestamp())
end`,
			`call("foo");`,
			"",
		),
	)
}

func TestLuaExecutorGetSet(t *testing.T) {
	log.SetLevel(btclog.DebugLvl)

	bc := loadBlockChain(t)
	defer bc.cleanup()

	bc.connectBlock(
		newLuaTxDef(defaultContract),
		newLuaTxEx(
			defaultUser,
			defaultContract,
			`
local system = require("system")
function set(key, value)
  system.setItem(key, value)
end
function dump(key)
  system.print(key .. ":" .. system.getItem(key))
end`,
			`call("set", "testkey1", "stored value")`,
		),
	)

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			`local system = require("system")
function set(key, value)
  system.setItem(key, value)
end
function dump(key)
  system.print(key .. ":" .. system.getItem(key))
end`,
			`call("dump", "testkey1")`,
		),
	)

	bc.connectBlock()
}

func getValue(state *lua.LState, def string) lua.LValue {
	_ = state.DoString(def)
	value := state.Get(-1)
	return value
}

func TestMarshallingJSON(t *testing.T) {
	state := lua.NewState()
	defer state.Close()

	stringValue := getValue(state, `return "true"`)

	tempLuaObj := luaJson.NewJsonValue(stringValue)
	jsonValue, err := tempLuaObj.MarshalJSON()
	if err != nil {
		t.Error(err)
	}

	fmt.Printf("[%v]\n", string(jsonValue))
}

func TestLuaSimpleContract(t *testing.T) {
	log.SetLevel(btclog.DebugLvl)

	bc := loadBlockChain(t)
	defer bc.cleanup()

	definition := `
    local system = require("system");
		function addCandidate(name)
			if system.getSender() ~= system.getCreator() then
				return
			end

			if (system.getItem(name) ~= nil) then
				return
			end
			
			local numCandidates;
			if (system.getItem("numCandidates") == nil) then
				numCandidates = 0;
			else
				numCandidates = tonumber(system.getItem("numCandidates"))
			end

			system.setItem("candidate_list_" .. numCandidates, name)

			numCandidates = numCandidates + 1;
			system.setItem("numCandidates", tostring(numCandidates));
			system.setItem(name, tostring(0));
		end
		function getCandidates()
			local numCandidates;
			local candidates = {};
			if (system.getItem("numCandidates") == nil) then
				return candidates;
			else
				numCandidates = tonumber(system.getItem("numCandidates"))
			end

			local i = 0;
			while true do
				if (numCandidates == i) then
					break;
				end
				local candidate = system.getItem("candidate_list_" .. i)
				local count = system.getItem(candidate)
				if count == nil then
					count = 0
				end
				table.insert(candidates, {id = i, name = candidate, count = count});
				i = i + 1;
			end
			return candidates;
		end
		function registerVoter(address)
			if system.getSender() ~= system.getCreator() then
				return
			end
			
			system.setItem("voter_" .. address, "0");
		end
		function vote(candidateID)
            local totalVoted
			if system.getItem("voter_" .. system.getSender()) == nil then
				return
			end
            totalVoted = tonumber(system.getItem("voter_" .. system.getSender()))
            if totalVoted > 3 then
                return
            end
            system.print("casted votes " .. tostring(totalVoted))
			if system.getItem(candidateID) == nil then
				return
			end
			local currentVotes;
			if (system.getItem(candidateID) == nil) then
				currentVotes = 0;
			else
				currentVotes = tonumber(system.getItem(candidateID))
			end
			currentVotes = currentVotes + 1

			system.setItem(candidateID, tostring(currentVotes))
			system.print("candidate " .. candidateID .. " : " .. system.getItem(candidateID))
            totalVoted = totalVoted + 1
			system.setItem("voter_" .. system.getSender(), tostring(totalVoted));
		end
		`

	bc.connectBlock(
		newLuaTxDef("address1"),
		newLuaTxEx(
			"address1",
			"address1",
			definition,
			`call("addCandidate", "candidate1")`,
		),
		newLuaTxEx(
			"address1",
			"address1",
			definition,
			`call("addCandidate", "candidate2")`,
		),
		newLuaTxEx(
			"address1",
			"address1",
			definition,
			`call("addCandidate", "candidate3")`,
		),
	)

	bc.view(
		newLuaQuery(
			"address2",
			"address1",
			definition,
			`return call("getCandidates")`,
			"",
		),
	)
	bc.connectBlock(
		newLuaTxEx(
			"address2",
			"address1",
			definition,
			`call("addCandidate", "candidate4")`,
		),
	)
	bc.view(
		newLuaQuery(
			"address2",
			"address1",
			definition,
			`return call("getCandidates")`,
			"",
		),
	)

	bc.connectBlock(
		// register voter
		newLuaTxEx(
			"address1",
			"address1",
			definition,
			`call("registerVoter", "address10")`,
		),
		newLuaTxEx(
			"address1",
			"address1",
			definition,
			`call("registerVoter", "address10")`,
		),
		newLuaTxEx(
			"address1",
			"address1",
			definition,
			`call("registerVoter", "address11")`,
		),
		newLuaTxEx(
			"address1",
			"address1",
			definition,
			`call("registerVoter", "address1")`,
		),
		// vote
		newLuaTxEx(
			"address1",
			"address1",
			definition,
			`call("vote", "address1")`,
		),
		newLuaTxEx(
			"address1",
			"address1",
			definition,
			`call("vote", "address1")`,
		),
		newLuaTxEx(
			"address1",
			"address1",
			definition,
			`call("vote", "address2")`,
		),
		newLuaTxEx(
			"address1",
			"address1",
			definition,
			`call("vote", "address2")`,
		),
		newLuaTxEx(
			"address1",
			"address1",
			definition,
			`call("vote", "address3")`,
		),
	)

	bc.view(
		newLuaQuery(
			"address1",
			"address1",
			definition,
			`return call("getCandidates")`,
			"",
		),
	)

	bc.connectBlock(
		newLuaTxEx(
			"address11",
			"address1",
			definition,
			`call("vote", "candidate1")`,
		),
		newLuaTxEx(
			"address11",
			"address1",
			definition,
			`return call("getCandidates")`,
		),
	)
}

func TestInfiniteLoop(t *testing.T) {
	log.SetLevel(btclog.TraceLvl)
	sql.UseLogger(log)

	bc := loadBlockChain(t)
	defer bc.cleanup()

	definition := `
local system = require("system")

function infiniteLoop()
	for i = 1, 100000000000000 do
		system.setItem("key_"..i, "value_"..i)
	end
end
`
	bc.connectBlock(
		newLuaTxDef(defaultContract),
		newLuaTxExFail(
			defaultUser,
			defaultContract,
			definition,
			`call("infiniteLoop")`,
			"exceeded the maximum instruction count",
		),
	)
}

func TestSqlVmSimple(t *testing.T) {
	log.SetLevel(btclog.TraceLvl)
	sql.UseLogger(log)

	bc := loadBlockChain(t)
	defer bc.cleanup()

	definition := `
local system = require("system")
local db = require("db")

function createAndInsert()
    db.exec("create table if not exists dual(dummy char(1))")
	db.exec("insert into dual values ('X')")
    local insertYZ = db.prepare("insert into dual values (?),(?)")
    insertYZ:exec("Y", "Z")
end

function insertRollbackData()
	db.exec("insert into dual values ('A'),('B'),('C')")
end

function query()
    local rt = {}
    local stmt = db.prepare("select ?+1, round(?,1), dummy || ? as col3 from dual order by col3")
    local rs = stmt:query(1, 3.14, " Hello Blockchain")
    while rs:next() do
        local col1, col2, col3 = rs:get()
        table.insert(rt, col1)
        table.insert(rt, col2)
        table.insert(rt, col3)
    end
    return rt
end

function count()
	local rs = db.query("select count(*) from dual")
	if rs:next() then
		local n = rs:get()
		--rs:next()
		return n
	else
		return "error in count()"
	end
end

function all()
    local rt = {}
    local rs = db.query("select dummy from dual order by 1")
    while rs:next() do
        local col = rs:get()
        table.insert(rt, col)
    end
    return rt
end
`

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("createAndInsert")`,
		),
	)

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("query"); return res`,
			`[2,3.1,"X Hello Blockchain",2,3.1,"Y Hello Blockchain",2,3.1,"Z Hello Blockchain"]`,
		),
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("count"); return res`,
			`3`,
		),
	)

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("count"); return res`,
			`3`,
		),
	)

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("insertRollbackData")`,
		),
	)

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("count"); return res`,
			`6`,
		),
	)

	bc.disconnectBlock()

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("count"); return res`,
			`3`,
		),
	)
}

func TestSqlVmFirstDB(t *testing.T) {
	log.SetLevel(btclog.TraceLvl)
	sql.UseLogger(log)

	bc := loadBlockChain(t)
	defer bc.cleanup()

	definition := `
local system = require("system")
local db = require("db")

function createAndInsert()
    db.exec("create table if not exists dual(dummy char(1))")
	db.exec("insert into dual values ('X')")
end

function insert2()
	db.exec("insert into dual values ('Y'),('Z')")
end

function count()
	local rs = db.query("select count(*) from dual")
	if rs:next() then
		local n = rs:get()
		return n
	else
		return "error in count()"
	end
end
`

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("createAndInsert")`,
		),
	)

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("insert2")`,
		),
	)

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("count"); return res`,
			`3`,
		),
	)

	bc.disconnectBlock()

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("count"); return res`,
			`1`,
		),
	)

	bc.disconnectBlock()

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("count"); return res`,
			`"error in count()"`,
		),
	)
}

func TestSqlVmFail(t *testing.T) {
	log.SetLevel(btclog.TraceLvl)
	sql.UseLogger(log)

	bc := loadBlockChain(t)
	defer bc.cleanup()

	definition := `
local system = require("system")
local db = require("db")

function init()
    db.exec("create table if not exists total(n int)")
	db.exec("insert into total values (0)")
end

function add(n)
	local stmt = db.prepare("update total set n = n + ?")
	stmt:exec(n)
end

function addFail(n)
	local stmt = db.prepare("update set n = n + ?")
	stmt:exec(n)
end

function get()
	local rs = db.query("select n from total")
	rs:next()
	n = rs:get()
	return n
end
`

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("init")`,
		),
	)

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("add", 1)`,
		),
	)

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("add", 2)`,
		),
		newLuaTxExFail(
			defaultUser,
			defaultContract,
			definition,
			`call("addFail", 3)`,
			"near \"set\": syntax error",
		),
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("add", 4)`,
		),
	)

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("add", 5)`,
		),
	)

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("get"); return res`,
			`12`,
		),
	)

	bc.disconnectBlock()

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("get"); return res`,
			`7`,
		),
	)
}

func TestSqlVmDateTime(t *testing.T) {
	log.SetLevel(btclog.TraceLvl)
	sql.UseLogger(log)

	bc := loadBlockChain(t)
	defer bc.cleanup()

	definition := `
local system = require("system")
local db = require("db")

function init()
    db.exec("create table if not exists dt_test (n datetime, b bool)")
	db.exec("insert into dt_test values (10000, 1),(date('2004-10-24', '+1 month', '-1 day'), 0)")
end

function nowNull()
	db.exec("insert into dt_test values (date('now'), 0)")
end

function localtimeNull()
	db.exec("insert into dt_test values (datetime('2018-05-25', 'localtime'), 1)")
end

function get()
	local rs = db.query("select n, b from dt_test order by 1, 2")
	local r = {}
	while rs:next() do
		local d, b = rs:get()
		table.insert(r, { date= d, bool= b })
	end
	return r
end
`

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("init")`,
		),
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("nowNull")`,
		),
	)
	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("localtimeNull")`,
		),
	)
	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("get"); return res`,
			`[{"bool":0},{"bool":1},{"bool":1,"date":"1970-01-01T02:46:40Z"},{"bool":0,"date":"2004-11-23T00:00:00Z"}]`,
		),
	)
}

func TestSqlConstraints(t *testing.T) {
	log.SetLevel(btclog.TraceLvl)
	sql.UseLogger(log)

	bc := loadBlockChain(t)
	defer bc.cleanup()

	definition := `
local system = require("system")
local db = require("db")

function init()
    db.exec([[create table if not exists r (
  id integer primary key
, n integer check(n >= 10)
, nonull text not null
, only integer unique)
]])
    db.exec("insert into r values (1, 11, 'text', 1)")
	db.exec("create table if not exists s (rid integer references r(id))")
end

function pkFail()
	db.exec("insert into r values (1, 12, 'text', 2)")
end

function checkFail()
	db.exec("insert into r values (2, 9, 'text', 3)")
end

function fkFail()
	db.exec("insert into s values (2)")
end

function notNullFail()
	db.exec("insert into r values (2, 13, null, 2)")
end

function uniqueFail()
	db.exec("insert into r values (2, 13, 'text', 1)")
end
`

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("init")`,
		),
		newLuaTxExFail(
			defaultUser,
			defaultContract,
			definition,
			`call("pkFail")`,
			"UNIQUE constraint failed: r.id",
		),
		newLuaTxExFail(
			defaultUser,
			defaultContract,
			definition,
			`call("checkFail")`,
			"CHECK constraint failed: r",
		),
		newLuaTxExFail(
			defaultUser,
			defaultContract,
			definition,
			`call("fkFail")`,
			"FOREIGN KEY constraint failed",
		),
		newLuaTxExFail(
			defaultUser,
			defaultContract,
			definition,
			`invoke("notNullFail")`,
			"NOT NULL constraint failed: r.nonull",
		),
		newLuaTxExFail(
			defaultUser,
			defaultContract,
			definition,
			`invoke("uniqueFail")`,
			"UNIQUE constraint failed: r.only",
		),
	)
}

func TestSqlVmCustomer(t *testing.T) {
	log.SetLevel(btclog.TraceLvl)
	sql.UseLogger(log)

	bc := loadBlockChain(t)
	defer bc.cleanup()

	definition := `
local system = require("system")
local db = require("db")

function createTable()
  db.exec([[create table if not exists customer(
        id varchar(10),
        passwd varchar(20),
        name varchar(30),
        birth char(8),
        mobile varchar(20)
    )]])
end

function query(id)
    local rt = {}
    local stmt = db.prepare("select * from customer where id like '%' || ? || '%'")
    local rs = stmt:query(id)
    while rs:next() do
        local col1, col2, col3, col4, col5 = rs:get()
        local item = {
                    id = col1,
                    passwd = col2,
                    name = col3,
                    birth = col4,
                    mobile = col5
            }
        table.insert(rt, item)
    end
    return rt
end



function insert(id , passwd, name, birth, mobile )
    local stmt = db.prepare("insert into customer values (?,?,?,?,?)")
    stmt:exec(id, passwd, name, birth, mobile)
end

function update(id , passwd )
    local stmt = db.prepare("update customer set passwd =? where id =?")
    stmt:exec(passwd, id)
end

function delete(id)
    local stmt = db.prepare("delete from customer where id =?")
    stmt:exec(id)
end

function count()
	local rs = db.query("select count(*) from customer")
	if rs:next() then
		local n = rs:get()
		return n
	else
		return "error in count()"
	end
end
`

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("createTable")`,
		),
	)

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("insert","id1","passwd1","name1","20180524","010-1234-5678")`,
		),
	)

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("insert","id2","passwd2","name2","20180524","010-1234-5678")`,
		),
	)

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("update","id2","passwd3")`,
		),
	)

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("count"); return res`,
			`2`,
		),
	)

	bc.disconnectBlock()

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("query","id2"); return res`,
			`[{"birth":"20180524","id":"id2","mobile":"010-1234-5678","name":"name2","passwd":"passwd2"}]`,
		),
	)

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("delete","id2")`,
		),
	)

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("query","id2"); return res`,
			`{}`,
		),
	)
}

func TestSqlVmDataType(t *testing.T) {
	log.SetLevel(btclog.TraceLvl)
	sql.UseLogger(log)

	bc := loadBlockChain(t)
	defer bc.cleanup()

	definition := `
local system = require("system")
local db = require("db")

function createDataTypeTable()
  db.exec([[create table if not exists datatype_table(
        var1 varchar(10),
        char1 char(10),
        int1 int(5),
        float1 float(6),
        blockheight1 long
    )]])
end

function dropDataTypeTable()
   db.exec("drop table datatype_table")
end


function insertDataTypeTable()
    local stmt = db.prepare("insert into datatype_table values ('ABCD','fgh',1,3.14,?)")
    stmt:exec(system.getBlockheight())
end

function queryOrderByDesc()
    local rt = {}
    local rs = db.query("select * from datatype_table order by blockheight1 desc")
    while rs:next() do
        local col1, col2, col3, col4, col5 = rs:get()
        item = {
                    var1 = col1,
                    char1 = col2,
                    int1 = col3,
                    float1 = col4,
                    blockheight1 = col5
            }
        table.insert(rt, item)
    end
    return rt
end

function queryGroupByBlockheight1()
    local rt = {}
    local rs = db.query("select blockheight1, count(*), sum(int1), avg(float1) from datatype_table group by blockheight1")
    while rs:next() do
        local col1, col2, col3, col4 = rs:get()
        item = {
                    blockheight1 = col1,
                    count1 = col2,
                    sum_int1 = col3,
                    avg_float1 =col4
            }
        table.insert(rt, item)
    end
    return rt
end
`
	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("createDataTypeTable")`,
		),
	)

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("insertDataTypeTable")`,
		),
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("insertDataTypeTable")`,
		),
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("insertDataTypeTable")`,
		),
	)

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("insertDataTypeTable")`,
		),
	)

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("queryOrderByDesc"); return res`,
			`[{"blockheight1":0,"char1":"fgh","float1":3.14,"int1":1,"var1":"ABCD"},{"blockheight1":0,"char1":"fgh","float1":3.14,"int1":1,"var1":"ABCD"},{"blockheight1":0,"char1":"fgh","float1":3.14,"int1":1,"var1":"ABCD"},{"blockheight1":0,"char1":"fgh","float1":3.14,"int1":1,"var1":"ABCD"}]`,
		),
	)

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("queryGroupByBlockheight1"); return res`,
			`[{"avg_float1":3.14,"blockheight1":0,"count1":4,"sum_int1":4}]`,
		),
	)
}

func TestSqlVmFunction(t *testing.T) {
	log.SetLevel(btclog.TraceLvl)
	sql.UseLogger(log)

	bc := loadBlockChain(t)
	defer bc.cleanup()

	definition := `
local system = require("system")
local db = require("db")

function sql_func()
    local rt = {}
    local rs = db.query("select round(3.14),min(1,2,3), max(4,5,6)")
	if rs:next() then
	    local col1, col2, col3 = rs:get()
        table.insert(rt, col1)
        table.insert(rt, col2)
        table.insert(rt, col3)
        return rt
	else
		return "error in func()"
	end
end

function abs_func()
    local rt = {}
    local rs = db.query("select abs(-1),abs(0), abs(1)")
	if rs:next() then
	    local col1, col2, col3 = rs:get()
        table.insert(rt, col1)
        table.insert(rt, col2)
        table.insert(rt, col3)
        return rt
	else
		return "error in abs()"
	end
end

function typeof_func()
    local rt = {}
    local rs = db.query("select typeof(-1), typeof('abc'), typeof(3.14), typeof(null)")
	if rs:next() then
	    local col1, col2, col3, col4 = rs:get()
        table.insert(rt, col1)
        table.insert(rt, col2)
        table.insert(rt, col3)
        table.insert(rt, col4)
        return rt
	else
		return "error in typeof()"
	end
end
`

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("sql_func"); return res`,
			`[3,1,6]`,
		),
	)

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("abs_func"); return res`,
			`[1,0,1]`,
		),
	)

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("typeof_func"); return res`,
			`["integer","text","real","null"]`,
		),
	)
}

func TestSqlVmBook(t *testing.T) {
	log.SetLevel(btclog.TraceLvl)
	sql.UseLogger(log)

	bc := loadBlockChain(t)
	defer bc.cleanup()

	definition := `
local system = require("system")
local db = require("db")

function createTable()
  db.exec([[create table if not exists book (
        page number,
        contents text
    )]])

  db.exec([[create table if not exists copy_book (
        page number,
        contents text
    )]])

end

function makeBook()
   	local stmt = db.prepare("insert into book values (?,?)")
	for i = 1, 100 do    
   		stmt:exec(i, "value=" .. i*i)
    end
end

function copyBook()
    local rs = db.query("select page, contents from book order by page asc")
    while rs:next() do
        local col1, col2 = rs:get()
        local stmt_t = db.prepare("insert into copy_book values (?,?)")
        stmt_t:exec(col1, col2)
    end
end


function viewCopyBook()
    local rt = {}
    local rs = db.query("select max(page), min(contents) from copy_book")
    while rs:next() do
        local col1, col2 = rs:get()
        table.insert(rt, col1)
		table.insert(rt, col2)
    end
    return rt
end

function viewJoinBook()
    local rt = {}
    local rs = db.query([[select c.page, b.page, c.contents  
							from copy_book c, book b 
							where c.page = b.page and c.page = 10 ]])
    while rs:next() do
        local col1, col2, col3 = rs:get()
        table.insert(rt, col1)
		table.insert(rt, col2)
		table.insert(rt, col3)
    end
    return rt
end
`
	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("createTable")`,
		),
	)

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("makeBook")`,
		),
	)

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("copyBook")`,
		),
	)

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("viewCopyBook"); return res`,
			`[100,"value=1"]`,
		),
	)

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("viewJoinBook"); return res`,
			`[10,10,"value=100"]`,
		),
	)
}
func TestSqlVmDateformat(t *testing.T) {
	log.SetLevel(btclog.TraceLvl)
	sql.UseLogger(log)

	bc := loadBlockChain(t)
	defer bc.cleanup()

	definition := `
local system = require("system")
local db = require("db")

function init()
db.exec("drop table if exists dateformat_test")
db.exec([[create table if not exists dateformat_test
(
	col1 date ,
	col2 datetime ,
	col3 text
)]])
db.exec("insert into dateformat_test values (date('2004-10-24 11:11:11'), datetime('2004-10-24 11:11:11'),strftime('%Y%m%d%H%M%S','2004-10-24 11:11:11'))")
db.exec("insert into dateformat_test values (date(1527504338,'unixepoch'), datetime(1527504338,'unixepoch'), strftime('%Y%m%d%H%M%S',1527504338,'unixepoch') )")
end

function get()
    local rt = {}
    local rs = db.query([[select col1, col2, col3
                            from dateformat_test ]])
    while rs:next() do
        local col1, col2, col3 = rs:get()
        table.insert(rt, {col1,col2,col3} )
    end
    return rt
end
`

	bc.connectBlock(
		newLuaTxEx(
			defaultUser,
			defaultContract,
			definition,
			`call("init")`,
		),
	)

	bc.view(
		newLuaQuery(
			defaultUser,
			defaultContract,
			definition,
			`res = call("get"); return res`,
			`[["2004-10-24T00:00:00Z","2004-10-24T11:11:11Z","20041024111111"],["2018-05-28T00:00:00Z","2018-05-28T10:45:38Z","20180528104538"]]`,
		),
	)
}
