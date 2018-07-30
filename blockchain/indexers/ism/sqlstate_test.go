// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ism

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/coinstack/coinstackd/blockchain/indexers/ism/sql"
	"github.com/coinstack/coinstackd/database"
	_ "github.com/coinstack/coinstackd/database/ffldb"
)

var stage = 1

func connectBlock(db database.DB, state *SQLState, ismState *State, txs func()) error {
	return db.Update(func(tx database.Tx) error {
		ismState.NewStage(tx, []byte(fmt.Sprintf("STAGE-%d", stage)))
		stage++
		err := state.NewStage(tx)
		if err != nil {
			return err
		}
		txs()
		err = state.CloseStage(tx)
		if err != nil {
			return err
		}
		return nil
	})
}

func disconnectBlock(db database.DB, state *SQLState, ismState *State) error {
	return db.Update(func(tx database.Tx) error {
		stage--
		currentStageKey := []byte(fmt.Sprintf("STAGE-%d", stage))
		prevStageKey := []byte(fmt.Sprintf("STAGE-%d", stage-1))
		err := ismState.UndoStage(tx, currentStageKey, prevStageKey)
		if err != nil {
			return err
		}
		return state.UndoStage(tx)
	})
}

func newQueryer(sqlState *SQLState, instance, query string, rowConsumer func(rows *sql.Rows) error) error {
	tx, err := sqlState.ReadOnlyTx(instance)
	if err != nil {
		return err
	}
	rows, err := tx.Query(query)
	if err != nil {
		return err
	}
	err = rowConsumer(rows)
	if err != nil {
		return err
	}
	return tx.Rollback()
}

func TestISMSQLState(t *testing.T) {
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

	ismState := NewState()
	tempPath, _ := ioutil.TempDir(os.TempDir(), "test-sqlite")
	t.Logf("dbpath : %v", tempPath)

	t.Log("testing sqlstate")
	err = sql.LoadDatabase(tempPath)
	if err != nil {
		t.Errorf("Failed to create test database (%s) %v", "sqldb", err)
	}
	sqlState := NewSQLState(ismState)

	if err := idb.Update(func(tx database.Tx) error {
		ismState.Create(tx)
		sqlState.Init(tx)
		return nil
	}); err != nil {
		t.Fatal("failed to execute - ", err)
	}

	var n int64
	var s string
	var pi float64

	err = connectBlock(idb, sqlState, ismState, func() {
		sqlTx, err := sqlState.Tx("TX-1")
		if err != nil {
			t.Error(err)
		}
		sqlTx.Exec(`create table foo (id integer, name text)`)
		rs, err := sqlTx.Query(`select count(1), "foo", 3.14 from foo`)
		if err != nil {
			t.Error(err)
		}
		rs.Next()
		rs.Scan(&n, &s, &pi)
		if n != 0 {
			t.Errorf("expected: 0, but got %d\n", n)
		}
		rs.Close()

		sqlTx, err = sqlState.Tx("TX-2")
		if err != nil {
			t.Error(err)
		}
		sqlTx.Exec(`create table foo (id integer, name text)`)
		sqlTx.Exec(`insert into foo(id, name) values(5, "test5")`)
		sqlTx.Exec(`insert into foo(id, name) values(5, "test5")`)
		rs, err = sqlTx.Query(`select count(1), "foo", 3.14 from foo;`)
		if err != nil {
			t.Error(err)
		}
		rs.Next()
		rs.Scan(&n, &s, &pi)
		if n != 2 {
			t.Errorf("expected: 2, but got: %d\n", n)
		}
		rs.Close()
	})
	if err != nil {
		t.Error(err)
	}

	err = connectBlock(idb, sqlState, ismState, func() {
		sqlTx, err := sqlState.Tx("TX-1")
		if err != nil {
			t.Error(err)
		}
		sqlTx.Exec(`insert into foo(id, name) values(5, "test5")`)
		rs, err := sqlTx.Query(`select count(1), "foo", 3.14 from foo;`)
		if err != nil {
			t.Error(err)
		}
		rs.Next()
		rs.Scan(&n, &s, &pi)
		if n != 1 {
			t.Errorf("expected: 1, but got: %d\n", n)
		}
		rs.Close()
	})
	if err != nil {
		t.Error(err)
	}

	connectBlock(idb, sqlState, ismState, func() {})
	connectBlock(idb, sqlState, ismState, func() {})
	disconnectBlock(idb, sqlState, ismState)
	disconnectBlock(idb, sqlState, ismState)

	err = connectBlock(idb, sqlState, ismState, func() {
		sqlTx, err := sqlState.Tx("TX-1")
		if err != nil {
			t.Error(err)
		}
		sqlTx.Exec(`insert into foo(id, name) values(5, "test5")`)
		rs, _ := sqlTx.Query(`select count(1), "foo", 3.14 from foo;`)
		rs.Next()
		rs.Scan(&n, &s, &pi)
		if n != 2 {
			t.Errorf("expected: 2, but got: %d\n", n)
		}
		rs.Close()
		sqlTx, err = sqlState.Tx("TX-2")
		if err != nil {
			t.Error(err)
		}
		sqlTx.Exec(`insert into foo(id, name) values(5, "test5")`)
		rs, _ = sqlTx.Query(`select count(1), "foo", 3.14 from foo;`)
		rs.Next()
		rs.Scan(&n, &s, &pi)
		if n != 3 {
			t.Errorf("expected: 3, but got: %d\n", n)
		}
		rs.Close()
	})
	if err != nil {
		t.Error(err)
	}

	disconnectBlock(idb, sqlState, ismState)

	connectBlock(idb, sqlState, ismState, func() {
		sqlTx, err := sqlState.Tx("TX-1")
		if err != nil {
			t.Error(err)
		}
		rs, _ := sqlTx.Query(`select count(1), "foo", 3.14 from foo;`)
		rs.Next()
		rs.Scan(&n, &s, &pi)
		if n != 1 {
			t.Errorf("expected: 1, but got: %d\n", n)
		}
		rs.Close()

		sqlTx, err = sqlState.Tx("TX-2")
		if err != nil {
			t.Error(err)
		}
		rs, _ = sqlTx.Query(`select count(1), "foo", 3.14 from foo;`)
		rs.Next()
		rs.Scan(&n, &s, &pi)
		if n != 2 {
			t.Errorf("expected: 2, but got: %d\n", n)
		}
		rs.Close()
	})
	if err != nil {
		t.Error(err)
	}

	err = connectBlock(idb, sqlState, ismState, func() {
		sqlTx, err := sqlState.Tx("TX-1")
		if err != nil {
			t.Error(err)
		}
		sqlTx.Exec(`insert into foo(id, name) values(5, "test5")`)
	})
	if err != nil {
		t.Error(err)
	}

	err = connectBlock(idb, sqlState, ismState, func() {
		sqlTx, err := sqlState.Tx("TX-1")
		if err != nil {
			t.Error(err)
		}
		sqlTx.Exec(`insert into foo(id, name) values(6, "test6")`)
	})
	if err != nil {
		t.Error(err)
	}

	err = connectBlock(idb, sqlState, ismState, func() {
		sqlTx, err := sqlState.Tx("TX-1")
		if err != nil {
			t.Error(err)
		}
		sqlTx.Exec(`insert into foo(id, name) values(1, "test")`)
		rs, _ := sqlTx.Query(`select count(1), "foo", 3.14 from foo;`)
		rs.Next()
		rs.Scan(&n, &s, &pi)
		if n != 4 {
			t.Errorf("expected: 4, but got: %d\n", n)
		}
		rs.Close()
	})
	if err != nil {
		t.Error(err)
	}

	err = connectBlock(idb, sqlState, ismState, func() {
		sqlTx, err := sqlState.Tx("TX-1")
		if err != nil {
			t.Error(err)
		}
		sqlTx.Exec(`insert into foo(id, name) values(2, "test2")`)
		rs, _ := sqlTx.Query(`select count(1), "foo", 3.14 from foo;`)
		rs.Next()
		rs.Scan(&n, &s, &pi)
		if n != 5 {
			t.Errorf("expected: 5, but got: %d\n", n)
		}
		rs.Close()
	})
	if err != nil {
		t.Error(err)
	}

	disconnectBlock(idb, sqlState, ismState)

	err = newQueryer(
		sqlState,
		"TX-1",
		`select count(1) from foo`,
		func(rows *sql.Rows) error {
			rows.Next()
			rows.Scan(&n)
			if n != 4 {
				t.Errorf("expected: 4, but got: %d\n", n)
			}
			return nil
		},
	)
	if err != nil {
		t.Error(err)
	}

	disconnectBlock(idb, sqlState, ismState)

	err = newQueryer(
		sqlState,
		"TX-1",
		`select count(1) from foo`, func(rows *sql.Rows) error {
			rows.Next()
			rows.Scan(&n)
			if n != 3 {
				t.Errorf("expected: 3, but got: %d\n", n)
			}
			rows.Close()
			return nil
		},
	)
	if err != nil {
		t.Error(err)
	}

	err = connectBlock(idb, sqlState, ismState, func() {
		sqlTx, err := sqlState.Tx("TX-1")
		if err != nil {
			t.Error(err)
		}
		sqlTx.Exec(`insert into foo(id, name) values(1, "test")`)
		sqlTx.Exec(`insert into foo(id, name) values(1, "test")`)
		rs, _ := sqlTx.Query(`select count(1), "foo", 3.14 from foo;`)
		rs.Next()
		rs.Scan(&n, &s, &pi)
		if n != 5 {
			t.Errorf("expected: 5, but got: %d\n", n)
		}
		rs.Close()
	})
	if err != nil {
		t.Error(err)
	}

	disconnectBlock(idb, sqlState, ismState)

	err = newQueryer(
		sqlState,
		"TX-1",
		`select count(1) from foo`,
		func(rows *sql.Rows) error {
			rows.Next()
			rows.Scan(&n)
			if n != 3 {
				t.Errorf("expected: 3, but got: %d\n", n)
			}
			rows.Close()
			return nil
		},
	)
	if err != nil {
		t.Error(err)
	}
}
