// Copyright (c) 2016 BLOCKO INC.
package txscript

import (
	"bytes"
	"errors"

	"github.com/coinstack/btcutil"
	"github.com/coinstack/coinstackd/chaincfg"
	"github.com/coinstack/btcutil/base58"
	"github.com/btcsuite/golangcrypto/ripemd160"
)

var (
	// perMarkerMagic is address data transaction marker
	addrDataMarkerMagic = []byte{0x4f, 0x5a} // OZ
)

type Op struct {
	Opcode string
	Data   []byte
}

func ParseScript(script []byte) ([]Op, error) {
	opcodes, err := parseScript(script)
	if nil != err {
		return nil, err
	}

	parsedOps := []Op{}
	for _, pop := range opcodes {
		opcodeName := pop.opcode.name
		op := Op{
			Opcode: opcodeName,
			Data:   pop.data,
		}
		parsedOps = append(parsedOps, op)
	}

	return parsedOps, nil
}

// encodeAddress returns a human-readable payment address given a ripemd160 hash
// and netID which encodes the bitcoin network and address type.  It is used
// in both pay-to-pubkey-hash (P2PKH) and pay-to-script-hash (P2SH) address
// encoding.
func encodeAddress(hash160 []byte, netID byte) string {
	// Format is 1 byte for a network and address class (i.e. P2PKH vs
	// P2SH), 20 bytes for a RIPEMD160 hash, and 4 bytes of checksum.
	return base58.CheckEncode(hash160[:ripemd160.Size], netID)
}

func ParseAddrDataScript(script []byte, chainParams *chaincfg.Params) (btcutil.Address, error) {

	opcodes, err := parseScript(script)
	if nil != err {
		return nil, err
	} else if len(opcodes) < 2 {
		return nil, errors.New("invalid nulldata type. a number of opcodes is not 2")
	} else if !isNullData(opcodes) {
		return nil, errors.New("this is not nulldata type tx")
	}

	payload := opcodes[1].data
	payloadLength := len(payload)

	// check marker magic
	if !bytes.HasPrefix(payload, addrDataMarkerMagic) { // stands for OZ
		return nil, errors.New("addr-data tx's magic byte (OZ) not found")
	}

	// payload lenght must be 24 bytes
	// 2 (magic bytes) + 2 (version byte) + 21 (pay-to-hash/pay-to-script + hash 160 address)
	if payloadLength != 25 {
		return nil, errors.New("payload length must be 25")
	}

	// enable this, if you need a version control....
	// majorVersion := uint16(payload[2])
	// minorVersion := uint16(payload[3])

	return btcutil.DecodeAddress(encodeAddress(payload[5:25], payload[4]), chainParams)
}
