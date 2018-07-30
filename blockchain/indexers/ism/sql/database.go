// Copyright (c) 2016 BLOCKO INC.
package sql

import (
	"errors"

	"github.com/coinstack/go-sqlite3"

	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"strings"
)

var (
	ErrDBOpen = errors.New("failed to open the sql database")
	ErrUndo   = errors.New("failed to undo the sql database")

	database = &Database{}
	load     sync.Once
)

const (
	pitrdbDriver = "pitrdb"
)

type Database struct {
	sync.RWMutex
	DBs        map[string]*DB
	OpenDbName string
	DataDir    string
}

func init() {
	sqlite3.SetErrLogHandler(func(code int, msg string) {
		log.Errorf("[SQLVM] ec: %d, msg: %s", code, msg)
	})
	sql.Register(pitrdbDriver, &sqlite3.SQLiteDriver{
		ConnectHook: func(conn *sqlite3.SQLiteConn) error {
			if _, ok := database.DBs[database.OpenDbName]; !ok {
				database.DBs[database.OpenDbName] = &DB{
					DB:   nil,
					tx:   nil,
					Conn: conn,
					name: database.OpenDbName,
				}
			} else {
				log.Warn("[SQLVM] duplicated connection")
			}
			return nil
		},
	})
}

func checkPath(path string) error {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		err = os.Mkdir(path, 0755)
	}
	return err
}

func LoadDatabase(dataDir string) error {
	var err error
	load.Do(func() {
		path := filepath.Join(dataDir, "sqldb")
		log.Tracef("[SQLVM] load database: %s", path)
		if err = checkPath(path); err == nil {
			database.DBs = make(map[string]*DB)
			database.DataDir = path
		}
	})
	return err
}

func LoadTestDatabase(dataDir string) error {
	var err error
	path := filepath.Join(dataDir, "sqldb")
	if err = checkPath(path); err == nil {
		database.DBs = make(map[string]*DB)
		database.DataDir = path
	}
	return err
}

func Close() {
	database.Lock()
	defer database.Unlock()

	for _, db := range database.DBs {
		_ = db.DB.Close()
	}
}

func RestoreRecoveryPoint(getRecoveryPoint func(instance string) []byte) error {
	database.RLock()
	defer database.RUnlock()

	for id, db := range database.DBs {
		storedRp := getRecoveryPoint(id)
		lastRp, err := db.Conn.GetLastRecoveryPoint()
		if err != nil {
			return err
		}
		switch bytes.Compare(storedRp, []byte(lastRp)) {
		case 0:
			continue
		case 1:
			return ErrUndo
		default: // -1
		}

		targetRp := string(storedRp)
		if targetRp == "" {
			targetRp = fmt.Sprintf("%s.db.0000000000000000", id)
		} else {
			firstRp, err := db.Conn.GetFirstRecoveryPoint()
			if err != nil {
				return err
			}
			if strings.Compare(firstRp, targetRp) > 0 {
				return err
			}
		}
		n, err := db.Conn.RestoreToPoint(targetRp)
		if err != nil {
			return err
		}
		log.Tracef(
			"[SQLVM] restore recovery point - db: %s, rp: %s, steps: %d",
			id,
			targetRp,
			n,
		)
	}
	return nil
}

func SaveRecoveryPoint(setRecoveryPoint func(instance, recoveryPoint string) error) error {
	database.RLock()
	defer database.RUnlock()

	for id, db := range database.DBs {
		if db.tx != nil {
			err := db.tx.Commit()
			if err != nil {
				return err
			}
			db.tx = nil
			rp, err := db.Conn.GetLastRecoveryPoint()
			if err != nil {
				return err
			}
			if len(rp) > 0 {
				log.Tracef("[SQLVM] save recovery point - db: %s, rp: %s", id, string(rp))
				setRecoveryPoint(id, rp)
			}
		}
	}
	return nil
}

func Begin(dbName string) (Tx, error) {
	db, err := Conn(dbName)
	if err != nil {
		return nil, err
	}
	return db.beginTx()
}

func BeginReadOnly(dbName string) (Tx, error) {
	db, err := Conn(dbName)
	if err != nil {
		return nil, err
	}
	return NewReadOnlyTx(db), nil
}

func Conn(dbName string) (*DB, error) {
	database.Lock()
	defer database.Unlock()

	if db, ok := database.DBs[dbName]; ok {
		return db, nil
	} else {
		return openDB(dbName)
	}
}

func openDB(dbName string) (*DB, error) {
	dbPath := filepath.Join(database.DataDir, dbName)
	if err := checkPath(dbPath); err != nil {
		return nil, err
	}
	database.OpenDbName = dbName
	dataSrc := fmt.Sprintf("file:%s/%s.db?pitr=on&pitr_limit=1440p&single_connection=true", dbPath, dbName)
	db, err := sql.Open(pitrdbDriver, dataSrc)
	if err != nil {
		return nil, ErrDBOpen
	}
	err = db.Ping()
	if err != nil {
		log.Critical(err.Error())
		delete(database.DBs, dbName)
		_ = db.Close()
		return nil, ErrDBOpen
	}
	database.DBs[dbName].DB = db
	return database.DBs[dbName], nil
}

type DB struct {
	*sql.DB
	sync.RWMutex
	tx   Tx
	Conn *sqlite3.SQLiteConn
	name string
}

func (db *DB) beginTx() (Tx, error) {
	log.Tracef("[SQLVM] begin tx - db: %s", db.name)
	if db.tx == nil {
		tx, err := db.Begin()
		if err != nil {
			return nil, err
		}
		db.tx = &WritableTx{
			TxCommon: TxCommon{db: db},
			Tx:       tx,
		}
	}
	return db.tx, nil
}

type Tx interface {
	Exec(query string, args ...interface{}) error
	Query(query string, args ...interface{}) (*Rows, error)
	Prepare(query string) (Stmt, error)
	Commit() error
	Rollback() error
	Savepoint() error
	Release() error
	RollbackToSavepoint() error
}

type TxCommon struct {
	db        *DB
	resources []Resource
}

type Resource interface {
	Close() error
}

func (t *TxCommon) addResource(r Resource) {
	if r != nil {
		t.resources = append(t.resources, r)
	}
}

func (t *TxCommon) removeResource(r Resource) {
	for i := 0; i < len(t.resources); i++ {
		if t.resources[i] == r {
			t.resources = append(t.resources[:i], t.resources[i+1:]...)
		}
	}
}

func (t *TxCommon) releaseResource() error {
	for _, r := range t.resources {
		if err := r.Close(); err != nil {
			return err
		}
	}
	return nil
}

type WritableTx struct {
	TxCommon
	*sql.Tx
}

func (tx *WritableTx) Exec(query string, args ...interface{}) error {
	if IsPermittedSql(query) {
		log.Tracef("[SQLVM] exec - db: %s, stmt: %s, args: %v", tx.db.name, query, args)
		_, err := tx.Tx.Exec(query, args...)
		return err
	} else {
		return errors.New("not permitted sql")
	}
}

func (tx *WritableTx) Query(query string, args ...interface{}) (*Rows, error) {
	if IsPermittedSql(query) {
		log.Tracef("[SQLVM] query - db:%s, stmt: %s, args: %v", tx.db.name, query, args)
		rows, err := tx.Tx.Query(query, args...)
		if err == nil {
			tx.addResource(rows)
		}
		return &Rows{Rows: rows}, err
	} else {
		return nil, errors.New("not permitted sql")
	}
}

func (tx *WritableTx) Commit() error {
	log.Tracef("[SQLVM] commit: %s", tx.db.name)
	tx.db.Lock()
	defer tx.db.Unlock()
	return tx.Tx.Commit()
}

func (tx *WritableTx) Rollback() error {
	log.Tracef("[SQLVM] rollback: %s", tx.db.name)
	tx.db.Lock()
	defer tx.db.Unlock()
	return tx.Tx.Rollback()
}

func (tx *WritableTx) Savepoint() error {
	log.Tracef("[SQLVM] savepoint: %s", tx.db.name)
	_, err := tx.Tx.Exec("SAVEPOINT \"" + tx.db.name + "\"")
	return err
}

func (tx *WritableTx) Release() error {
	log.Tracef("[SQLVM] release savepoint: %s", tx.db.name)
	err := tx.releaseResource()
	if err != nil {
		return err
	}
	_, err = tx.Tx.Exec("RELEASE SAVEPOINT \"" + tx.db.name + "\"")
	return err
}

func (tx *WritableTx) RollbackToSavepoint() error {
	log.Tracef("[SQLVM] rollback to savepoint: %s", tx.db.name)
	err := tx.releaseResource()
	if err != nil {
		return err
	}
	_, err = tx.Tx.Exec("ROLLBACK TO SAVEPOINT \"" + tx.db.name + "\"")
	return err
}

func (tx *WritableTx) Prepare(query string) (Stmt, error) {
	if IsPermittedSql(query) {
		log.Tracef("[SQLVM] tx prepare - db: %s, prepare: %s", tx.db.name, query)
		stmt, err := tx.Tx.Prepare(query)
		wStmt := &WritableStmt{
			StmtCommon: StmtCommon{
				Stmt:   stmt,
				dbName: tx.db.name,
				tx:     &tx.TxCommon,
			},
		}
		if err == nil {
			tx.addResource(wStmt)
		}
		return wStmt, err
	} else {
		return nil, errors.New("not permitted sql")
	}
}

type ReadOnlyTx struct {
	TxCommon
}

func NewReadOnlyTx(db *DB) Tx {
	tx := &ReadOnlyTx{
		TxCommon: TxCommon{db: db},
	}
	tx.db.RLock()
	return tx
}

func (tx *ReadOnlyTx) Exec(query string, args ...interface{}) error {
	return errors.New("only select queries allowed")
}

func (tx *ReadOnlyTx) Query(query string, args ...interface{}) (*Rows, error) {
	if IsPermittedReadOnlySql(query) {
		log.Tracef("[SQLVM] query - db:%s, stmt: %s, args: %v", tx.db.name, query, args)
		rows, err := tx.db.QueryContext(context.Background(), query, args...)
		if err == nil {
			tx.addResource(rows)
		}
		return &Rows{Rows: rows}, err
	} else {
		return nil, errors.New("only select queries allowed")
	}
}

func (tx *ReadOnlyTx) Commit() error {
	return errors.New("only select queries allowed")
}

func (tx *ReadOnlyTx) Rollback() error {
	log.Tracef("[SQLVM] read-only tx is closed")
	defer tx.db.RUnlock()
	return tx.releaseResource()
}

func (tx *ReadOnlyTx) Savepoint() error {
	return errors.New("only select queries allowed")
}

func (tx *ReadOnlyTx) Release() error {
	return errors.New("only select queries allowed")
}

func (tx *ReadOnlyTx) RollbackToSavepoint() error {
	return errors.New("only select queries allowed")
}

func (tx *ReadOnlyTx) Prepare(query string) (Stmt, error) {
	if IsPermittedReadOnlySql(query) {
		log.Tracef("[SQLVM] tx prepare - db: %s, prepare: %s", tx.db.name, query)
		stmt, err := tx.db.PrepareContext(context.Background(), query)
		rStmt := &ReadOnlyStmt{
			StmtCommon: StmtCommon{
				Stmt:   stmt,
				dbName: tx.db.name,
				tx:     &tx.TxCommon,
			},
		}
		if err == nil {
			tx.addResource(rStmt)
		}
		return rStmt, err
	} else {
		return nil, errors.New("only select queries allowed")
	}
}

type Stmt interface {
	Exec(args ...interface{}) error
	Query(args ...interface{}) (*Rows, error)
	Resource
}

type StmtCommon struct {
	*sql.Stmt
	dbName    string
	resources []Resource
	tx        *TxCommon
}

func (s *StmtCommon) addResource(r Resource) {
	if r != nil {
		s.resources = append(s.resources, r)
	}
}

func (s *StmtCommon) releaseResource() error {
	for _, r := range s.resources {
		if err := r.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (s *StmtCommon) release() {
	s.tx.removeResource(s)
}

func (s *StmtCommon) Close() error {
	if err := s.releaseResource(); err != nil {
		return err
	}
	return s.Stmt.Close()
}

type WritableStmt struct {
	StmtCommon
}

func (stmt *WritableStmt) Exec(args ...interface{}) error {
	log.Tracef("[SQLVM] stmt exec - db: %s, args: %v", stmt.dbName, args)
	_, err := stmt.Stmt.Exec(args...)
	if err != nil {
		stmt.release()
	}
	return err
}

func (stmt *WritableStmt) Query(args ...interface{}) (*Rows, error) {
	log.Tracef("[SQLVM] stmt query - db: %s, args: %s", stmt.dbName, args)
	rows, err := stmt.Stmt.Query(args...)
	if err == nil {
		stmt.addResource(rows)
	} else {
		stmt.release()
	}
	return &Rows{Rows: rows}, err
}

type ReadOnlyStmt struct {
	StmtCommon
}

func (stmt *ReadOnlyStmt) Exec(args ...interface{}) error {
	return errors.New("only select queries allowed")
}

func (stmt *ReadOnlyStmt) Query(args ...interface{}) (*Rows, error) {
	log.Tracef("[SQLVM] stmt query - db: %s, args: %s", stmt.dbName, args)
	rows, err := stmt.Stmt.Query(args...)
	if err == nil {
		stmt.addResource(rows)
	} else {
		stmt.release()
	}
	return &Rows{Rows: rows}, err
}

type Rows struct {
	*sql.Rows
}
