// Copyright (c) 2016 BLOCKO INC.
// Package sync comes from github.com/coinstack/coinstack-sync
// And this errors.go file comes from sync/errors.go of coinstack-sync
package sync

import (
	"fmt"
)

type DuplicateTxError struct {
}

func (e DuplicateTxError) Error() string {
	return "transaction is already in blockchain"
}

type IllegalTxError struct {
	Cause string
}

func (e IllegalTxError) Error() string {
	if len(e.Cause) > 0 {
		return fmt.Sprintf("transaction failed to pass verification - %v", e.Cause)
	}
	return "transaction failed to pass verification"
}

type OrphanedBlockError struct {
	hash string
}

func (e OrphanedBlockError) Error() string {
	return fmt.Sprintf("previous block not found %v", e.hash)
}
