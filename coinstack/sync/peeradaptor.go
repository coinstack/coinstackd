// Copyright (c) 2016 BLOCKO INC.
// Package sync comes from github.com/coinstack/coinstack-sync
// And this peeradaptor.go file comes from sync/peeradaptor.go of coinstack-sunc
// however this contains only partial contents of the file
package sync

// NetworkType is a type indicator of a current peer connection
type NetworkType int

// NetworkType has 4 types
const (
	MAINNET NetworkType = iota
	TESTNET
	REGTESTNET
	PRIVNET
)
