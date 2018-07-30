// Copyright (c) 2016 BLOCKO INC.
package ism

import (
	"errors"

	"github.com/coinstack/coinstackd/blockchain/indexers/ism/sql"
	"github.com/coinstack/coinstackd/database"
)

var (
	ismSQLRecoveryPoints = []byte("ismSQLRecoveryPoints")
)

type ISQLState interface {
	Init(dbTx database.Tx) error
	NewStage(dbTx database.Tx) error
	CloseStage(dbTx database.Tx) error
	UndoStage(dbTx database.Tx) error
	Tx(instance string) (sql.Tx, error)
	ReadOnlyTx(instance string) (sql.Tx, error)
}

type SQLState struct {
	ismState *State
}

func NewSQLState(ismState *State) *SQLState {
	return &SQLState{
		ismState: ismState,
	}
}

func (state *SQLState) Init(dbTx database.Tx) error {
	return state.ismState.CreateInstanceIfNotExist(dbTx, ismSQLRecoveryPoints)
}

func (state *SQLState) NewStage(dbTx database.Tx) error {
	if !state.ismState.HasInstance(dbTx, ismSQLRecoveryPoints) {
		return sql.ErrDBOpen
	}
	return sql.RestoreRecoveryPoint(
		func(instance string) []byte {
			return state.ismState.GetInstanceItem(dbTx, ismSQLRecoveryPoints, []byte(instance))
		},
	)
}

func (state *SQLState) CloseStage(dbTx database.Tx) error {
	if !state.ismState.HasInstance(dbTx, ismSQLRecoveryPoints) {
		return sql.ErrDBOpen
	}
	return sql.SaveRecoveryPoint(func(instance, recoveryPoint string) error {
		err := state.ismState.SetInstanceItem(dbTx, ismSQLRecoveryPoints, []byte(instance), []byte(recoveryPoint))
		if err != nil {
			return err
		}
		return state.ismState.Commit(dbTx, ismSQLRecoveryPoints)
	})
}

func (state *SQLState) UndoStage(dbTx database.Tx) error {
	return state.NewStage(dbTx)
}

func (state *SQLState) Tx(instance string) (sql.Tx, error) {
	return sql.Begin(instance)
}

func (state *SQLState) ReadOnlyTx(instance string) (sql.Tx, error) {
	return sql.BeginReadOnly(instance)
}

type NullSQLState struct{}

func NewNullSQLState() *NullSQLState {
	return &NullSQLState{}
}

func (*NullSQLState) Init(dbTx database.Tx) error {
	return nil
}

func (*NullSQLState) NewStage(dbTx database.Tx) error {
	return nil
}

func (*NullSQLState) CloseStage(dbTx database.Tx) error {
	return nil
}

func (*NullSQLState) UndoStage(dbTx database.Tx) error {
	return nil
}

func (*NullSQLState) Tx(instance string) (sql.Tx, error) {
	return nil, errors.New("SQL doesn't work in ephemeral mode")
}

func (*NullSQLState) ReadOnlyTx(instance string) (sql.Tx, error) {
	return nil, errors.New("SQL doesn't work in ephemeral mode")
}
