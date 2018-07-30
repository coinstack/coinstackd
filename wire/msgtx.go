// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wire

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
)

const (
	// TxVersion is the current latest supported transaction version.
	TxVersion = 1

	// MaxTxInSequenceNum is the maximum sequence number the sequence field
	// of a transaction input can be.
	MaxTxInSequenceNum uint32 = 0xffffffff

	// MaxPrevOutIndex is the maximum index the index field of a previous
	// outpoint can be.
	MaxPrevOutIndex uint32 = 0xffffffff
)

// defaultTxInOutAlloc is the default size used for the backing array for
// transaction inputs and outputs.  The array will dynamically grow as needed,
// but this figure is intended to provide enough space for the number of
// inputs and outputs in a typical transaction without needing to grow the
// backing array multiple times.
const defaultTxInOutAlloc = 15

const (
	// minTxInPayload is the minimum payload size for a transaction input.
	// PreviousOutPoint.Hash + PreviousOutPoint.Index 4 bytes + Varint for
	// SignatureScript length 1 byte + Sequence 4 bytes.
	minTxInPayload = 9 + HashSize

	// maxTxInPerMessage is the maximum number of transactions inputs that
	// a transaction which fits into a message could possibly have.
	maxTxInPerMessage = (MaxMessagePayload / minTxInPayload) + 1

	// minTxOutPayload is the minimum payload size for a transaction output.
	// Value 8 bytes + Varint for PkScript length 1 byte.
	minTxOutPayload = 9

	// maxTxOutPerMessage is the maximum number of transactions outputs that
	// a transaction which fits into a message could possibly have.
	maxTxOutPerMessage = (MaxMessagePayload / minTxOutPayload) + 1

	// minTxPayload is the minimum payload size for a transaction.  Note
	// that any realistically usable transaction must have at least one
	// input or output, but that is a rule enforced at a higher layer, so
	// it is intentionally not included here.
	// Version 4 bytes + Varint number of transaction inputs 1 byte + Varint
	// number of transaction outputs 1 byte + LockTime 4 bytes + min input
	// payload + min output payload.
	minTxPayload = 10
)

var (
	DeletedTxMarker  = []byte{0x44, 0x58} // DX
	DeletedTxVersion = []byte{0x01, 0x00} // v1.0
	DeletedTxOpTxID  = []byte{0x00, 0x01} // 0x0001
	DeletedTxOpAddr  = []byte{0x00, 0x02} // 0x0002
)

// nolint: golint
const (
	DeletedTxPayloadSize   = 0x46                     // 70 == (2+2+2) + (32+32)
	DeletedTxScriptMinSize = 2 + DeletedTxPayloadSize // OP_RETURN 0x46 PAYLOAD
)

// OutPoint defines a bitcoin data type that is used to track previous
// transaction outputs.
type OutPoint struct {
	Hash  ShaHash
	Index uint32
}

// NewOutPoint returns a new bitcoin transaction outpoint point with the
// provided hash and index.
func NewOutPoint(hash *ShaHash, index uint32) *OutPoint {
	return &OutPoint{
		Hash:  *hash,
		Index: index,
	}
}

// String returns the OutPoint in the human-readable form "hash:index".
func (o OutPoint) String() string {
	// Allocate enough for hash string, colon, and 10 digits.  Although
	// at the time of writing, the number of digits can be no greater than
	// the length of the decimal representation of maxTxOutPerMessage, the
	// maximum message payload may increase in the future and this
	// optimization may go unnoticed, so allocate space for 10 decimal
	// digits, which will fit any uint32.
	buf := make([]byte, 2*HashSize+1, 2*HashSize+1+10)
	copy(buf, o.Hash.String())
	buf[2*HashSize] = ':'
	buf = strconv.AppendUint(buf, uint64(o.Index), 10)
	return string(buf)
}

// TxIn defines a bitcoin transaction input.
type TxIn struct {
	PreviousOutPoint OutPoint
	SignatureScript  []byte
	Sequence         uint32
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction input.
func (t *TxIn) SerializeSize() int {
	// Outpoint Hash 32 bytes + Outpoint Index 4 bytes + Sequence 4 bytes +
	// serialized varint size for the length of SignatureScript +
	// SignatureScript bytes.
	return 40 + VarIntSerializeSize(uint64(len(t.SignatureScript))) +
		len(t.SignatureScript)
}

// NewTxIn returns a new bitcoin transaction input with the provided
// previous outpoint point and signature script with a default sequence of
// MaxTxInSequenceNum.
func NewTxIn(prevOut *OutPoint, signatureScript []byte) *TxIn {
	return &TxIn{
		PreviousOutPoint: *prevOut,
		SignatureScript:  signatureScript,
		Sequence:         MaxTxInSequenceNum,
	}
}

// TxOut defines a bitcoin transaction output.
type TxOut struct {
	Value    int64
	PkScript []byte
}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction output.
func (t *TxOut) SerializeSize() int {
	// Value 8 bytes + serialized varint size for the length of PkScript +
	// PkScript bytes.
	return 8 + VarIntSerializeSize(uint64(len(t.PkScript))) + len(t.PkScript)
}
func (t *TxOut) IsDeletable() bool {
	scr := t.PkScript
	scrLen := len(scr)
	// 0x6a == txscript.OP_RETURN
	if scr[0] == 0x6a && scrLen >= DeletedTxScriptMinSize {
		return true
	}
	return false
}

// NewTxOut returns a new bitcoin transaction output with the provided
// transaction value and public key script.
func NewTxOut(value int64, pkScript []byte) *TxOut {
	return &TxOut{
		Value:    value,
		PkScript: pkScript,
	}
}

// TxDel defines a transaction deleted.
type TxDel struct {
	TxHash  ShaHash
	SigHash ShaHash
}

func (t *TxDel) Payload(opCode []byte, size int) []byte {
	payload := make([]byte, size)
	copy(payload[0:2], DeletedTxMarker)
	copy(payload[2:4], DeletedTxVersion)
	copy(payload[4:6], opCode)
	copy(payload[6:38], t.TxHash.Bytes())
	copy(payload[38:70], t.SigHash.Bytes())
	return payload
}
func NewTxDel(txHash, sigHash *ShaHash) *TxDel {
	return &TxDel{
		TxHash:  *txHash,
		SigHash: *sigHash,
	}
}

// MsgTx implements the Message interface and represents a bitcoin tx message.
// It is used to deliver transaction information in response to a getdata
// message (MsgGetData) for a given transaction.
//
// Use the AddTxIn and AddTxOut functions to build up the list of transaction
// inputs and outputs.
type MsgTx struct {
	Version  int32
	TxIn     []*TxIn
	TxOut    []*TxOut
	LockTime uint32
	TxDel    *TxDel
}

// AddTxIn adds a transaction input to the message.
func (msg *MsgTx) AddTxIn(ti *TxIn) {
	msg.TxIn = append(msg.TxIn, ti)
}

// AddTxOut adds a transaction output to the message.
func (msg *MsgTx) AddTxOut(to *TxOut) {
	msg.TxOut = append(msg.TxOut, to)
}

func (msg *MsgTx) GetDataOut() (index int, to *TxOut) {
	for i, v := range msg.TxOut {
		// 0x6a == txscript.OP_RETURN
		if len(v.PkScript) > 0 && v.PkScript[0] == 0x6a {
			return i, v
		}
	}
	return -1, nil
}
func (msg *MsgTx) IsDeleted() bool {
	return msg.TxDel != nil
}
func (msg *MsgTx) HasDeletableTxOut() bool {
	i, to := msg.GetDataOut()
	if i < 0 {
		// data output not found
		return false
	}
	return to.IsDeletable()
}
func (msg *MsgTx) CheckDeleted() (*TxDel, error) {
	i, to := msg.GetDataOut()
	if i < 0 {
		// data output not found
		return nil, nil
	}
	scr := to.PkScript
	if len(scr) == 1 {
		return nil, nil
	}
	offset := getScriptOffset(scr[1])
	if offset <= 0 {
		return nil, nil
	}

	// 0x4458(DX), 0x0100(v1.0)
	if !bytes.Equal(scr[offset+0:offset+2], DeletedTxMarker) ||
		!bytes.Equal(scr[offset+2:offset+4], DeletedTxVersion) {
		return nil, nil
	}
	// 0x0001(OpTxID), 0x0002(OpAddr)
	if !bytes.Equal(scr[offset+4:offset+6], DeletedTxOpTxID) &&
		!bytes.Equal(scr[offset+4:offset+6], DeletedTxOpAddr) {
		return nil, nil
	}
	txHashBytes := scr[offset+6 : offset+38]
	sigHashBytes := scr[offset+38 : offset+70]
	sigHash := msg.TxSigHash(txHashBytes)
	if !bytes.Equal(sigHashBytes, sigHash.Bytes()) {
		return nil, fmt.Errorf("invalid sigHash=%s", sigHash.String())
	}
	txHash, err := NewShaHash(txHashBytes)
	if err != nil {
		return nil, err
	}
	return NewTxDel(txHash, &sigHash), nil
}
func getScriptOffset(in byte) int {
	// 0x01 == txscript.OP_DATA_1
	// 0x4b == txscript.OP_DATA_75
	// 0x4c == txscript.OP_PUSHDATA1
	// 0x4d == txscript.OP_PUSHDATA2
	// 0x4e == txscript.OP_PUSHDATA4
	if in >= 0x01 && in <= 0x4b {
		return 2
	}
	switch in {
	case 0x4c:
		return 3
	case 0x4d:
		return 4
	case 0x4e:
		return 6
	}
	return 0
}

// TxSha generates the ShaHash name for the transaction.
func (msg *MsgTx) TxSha() ShaHash {
	if msg.IsDeleted() {
		return msg.TxDel.TxHash
	}
	// Encode the transaction and calculate double sha256 on the result.
	// Ignore the error returns since the only way the encode could fail
	// is being out of memory or due to nil pointers, both of which would
	// cause a run-time panic.
	buf := bytes.NewBuffer(make([]byte, 0, msg.SerializeSize()))
	_ = msg.Serialize(buf)
	return DoubleSha256SH(buf.Bytes())
}
func (msg *MsgTx) TxSigHash(txHashBytes []byte) ShaHash {
	buf := new(bytes.Buffer)
	buf.Write(txHashBytes)
	for _, t := range msg.TxIn {
		buf.Write(t.SignatureScript)
	}
	return DoubleSha256SH(buf.Bytes())
}

// Copy creates a deep copy of a transaction so that the original does not get
// modified when the copy is manipulated.
func (msg *MsgTx) Copy() *MsgTx {
	// Create new tx and start by copying primitive values and making space
	// for the transaction inputs and outputs.
	newTx := MsgTx{
		Version:  msg.Version,
		TxIn:     make([]*TxIn, 0, len(msg.TxIn)),
		TxOut:    make([]*TxOut, 0, len(msg.TxOut)),
		LockTime: msg.LockTime,
	}

	// Deep copy the old TxIn data.
	for _, oldTxIn := range msg.TxIn {
		// Deep copy the old previous outpoint.
		oldOutPoint := oldTxIn.PreviousOutPoint
		newOutPoint := OutPoint{}
		newOutPoint.Hash.SetBytes(oldOutPoint.Hash[:])
		newOutPoint.Index = oldOutPoint.Index

		// Deep copy the old signature script.
		var newScript []byte
		oldScript := oldTxIn.SignatureScript
		oldScriptLen := len(oldScript)
		if oldScriptLen > 0 {
			newScript = make([]byte, oldScriptLen, oldScriptLen)
			copy(newScript, oldScript[:oldScriptLen])
		}

		// Create new txIn with the deep copied data and append it to
		// new Tx.
		newTxIn := TxIn{
			PreviousOutPoint: newOutPoint,
			SignatureScript:  newScript,
			Sequence:         oldTxIn.Sequence,
		}
		newTx.TxIn = append(newTx.TxIn, &newTxIn)
	}

	// Deep copy the old TxOut data.
	for _, oldTxOut := range msg.TxOut {
		// Deep copy the old PkScript
		var newScript []byte
		oldScript := oldTxOut.PkScript
		oldScriptLen := len(oldScript)
		if oldScriptLen > 0 {
			newScript = make([]byte, oldScriptLen, oldScriptLen)
			copy(newScript, oldScript[:oldScriptLen])
		}

		// Create new txOut with the deep copied data and append it to
		// new Tx.
		newTxOut := TxOut{
			Value:    oldTxOut.Value,
			PkScript: newScript,
		}
		newTx.TxOut = append(newTx.TxOut, &newTxOut)
	}

	if msg.TxDel != nil {
		newTx.TxDel = NewTxDel(&msg.TxDel.TxHash, &msg.TxDel.SigHash)
	}

	return &newTx
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding transactions stored to disk, such as in a
// database, as opposed to decoding transactions from the wire.
func (msg *MsgTx) BtcDecode(r io.Reader, pver uint32) error {
	var buf [4]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return err
	}
	msg.Version = int32(binary.LittleEndian.Uint32(buf[:]))

	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// Prevent more input transactions than could possibly fit into a
	// message.  It would be possible to cause memory exhaustion and panics
	// without a sane upper bound on this count.
	if count > uint64(maxTxInPerMessage) {
		str := fmt.Sprintf("too many input transactions to fit into "+
			"max message size [count %d, max %d]", count,
			maxTxInPerMessage)
		return messageError("MsgTx.BtcDecode", str)
	}

	msg.TxIn = make([]*TxIn, count)
	for i := uint64(0); i < count; i++ {
		ti := TxIn{}
		err = readTxIn(r, pver, msg.Version, &ti)
		if err != nil {
			return err
		}
		msg.TxIn[i] = &ti
	}

	count, err = ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// Prevent more output transactions than could possibly fit into a
	// message.  It would be possible to cause memory exhaustion and panics
	// without a sane upper bound on this count.
	if count > uint64(maxTxOutPerMessage) {
		str := fmt.Sprintf("too many output transactions to fit into "+
			"max message size [count %d, max %d]", count,
			maxTxOutPerMessage)
		return messageError("MsgTx.BtcDecode", str)
	}

	msg.TxOut = make([]*TxOut, count)
	for i := uint64(0); i < count; i++ {
		to := TxOut{}
		err = readTxOut(r, pver, msg.Version, &to)
		if err != nil {
			return err
		}
		msg.TxOut[i] = &to
	}

	_, err = io.ReadFull(r, buf[:])
	if err != nil {
		return err
	}
	msg.LockTime = binary.LittleEndian.Uint32(buf[:])

	msg.TxDel, err = msg.CheckDeleted()
	if err != nil {
		return err
	}
	return nil
}

// Deserialize decodes a transaction from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field in the transaction.  This function differs from BtcDecode
// in that BtcDecode decodes from the bitcoin wire protocol as it was sent
// across the network.  The wire encoding can technically differ depending on
// the protocol version and doesn't even really need to match the format of a
// stored transaction at all.  As of the time this comment was written, the
// encoded transaction is the same in both instances, but there is a distinct
// difference and separating the two allows the API to be flexible enough to
// deal with changes.
func (msg *MsgTx) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcDecode.
	return msg.BtcDecode(r, 0)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding transactions to be stored to disk, such as in a
// database, as opposed to encoding transactions for the wire.
func (msg *MsgTx) BtcEncode(w io.Writer, pver uint32) error {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], uint32(msg.Version))
	_, err := w.Write(buf[:])
	if err != nil {
		return err
	}

	count := uint64(len(msg.TxIn))
	err = WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, ti := range msg.TxIn {
		err = writeTxIn(w, pver, msg.Version, ti)
		if err != nil {
			return err
		}
	}

	count = uint64(len(msg.TxOut))
	err = WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, to := range msg.TxOut {
		err = writeTxOut(w, pver, msg.Version, to)
		if err != nil {
			return err
		}
	}

	binary.LittleEndian.PutUint32(buf[:], msg.LockTime)
	_, err = w.Write(buf[:])
	if err != nil {
		return err
	}
	return nil
}

// Serialize encodes the transaction to w using a format that suitable for
// long-term storage such as a database while respecting the Version field in
// the transaction.  This function differs from BtcEncode in that BtcEncode
// encodes the transaction to the bitcoin wire protocol in order to be sent
// across the network.  The wire encoding can technically differ depending on
// the protocol version and doesn't even really need to match the format of a
// stored transaction at all.  As of the time this comment was written, the
// encoded transaction is the same in both instances, but there is a distinct
// difference and separating the two allows the API to be flexible enough to
// deal with changes.
func (msg *MsgTx) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcEncode.
	return msg.BtcEncode(w, 0)

}

// SerializeSize returns the number of bytes it would take to serialize the
// the transaction.
func (msg *MsgTx) SerializeSize() int {
	// Version 4 bytes + LockTime 4 bytes + Serialized varint size for the
	// number of transaction inputs and outputs.
	n := 8 + VarIntSerializeSize(uint64(len(msg.TxIn))) +
		VarIntSerializeSize(uint64(len(msg.TxOut)))

	for _, txIn := range msg.TxIn {
		n += txIn.SerializeSize()
	}

	for _, txOut := range msg.TxOut {
		n += txOut.SerializeSize()
	}
	return n
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgTx) Command() string {
	return CmdTx
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgTx) MaxPayloadLength(pver uint32) uint32 {
	return MaxBlockPayload
}

// PkScriptLocs returns a slice containing the start of each public key script
// within the raw serialized transaction.  The caller can easily obtain the
// length of each script by using len on the script available via the
// appropriate transaction output entry.
func (msg *MsgTx) PkScriptLocs() []int {
	numTxOut := len(msg.TxOut)
	if numTxOut == 0 {
		return nil
	}

	// The starting offset in the serialized transaction of the first
	// transaction output is:
	//
	// Version 4 bytes + serialized varint size for the number of
	// transaction inputs and outputs + serialized size of each transaction
	// input.
	n := 4 + VarIntSerializeSize(uint64(len(msg.TxIn))) +
		VarIntSerializeSize(uint64(numTxOut))
	for _, txIn := range msg.TxIn {
		n += txIn.SerializeSize()
	}

	// Calculate and set the appropriate offset for each public key script.
	pkScriptLocs := make([]int, numTxOut)
	for i, txOut := range msg.TxOut {
		// The offset of the script in the transaction output is:
		//
		// Value 8 bytes + serialized varint size for the length of
		// PkScript.
		n += 8 + VarIntSerializeSize(uint64(len(txOut.PkScript)))
		pkScriptLocs[i] = n
		n += len(txOut.PkScript)
	}

	return pkScriptLocs
}

// NewMsgTx returns a new bitcoin tx message that conforms to the Message
// interface.  The return instance has a default version of TxVersion and there
// are no transaction inputs or outputs.  Also, the lock time is set to zero
// to indicate the transaction is valid immediately as opposed to some time in
// future.
func NewMsgTx() *MsgTx {
	return &MsgTx{
		Version: TxVersion,
		TxIn:    make([]*TxIn, 0, defaultTxInOutAlloc),
		TxOut:   make([]*TxOut, 0, defaultTxInOutAlloc),
	}
}

// readOutPoint reads the next sequence of bytes from r as an OutPoint.
func readOutPoint(r io.Reader, pver uint32, version int32, op *OutPoint) error {
	_, err := io.ReadFull(r, op.Hash[:])
	if err != nil {
		return err
	}

	var buf [4]byte
	_, err = io.ReadFull(r, buf[:])
	if err != nil {
		return err
	}
	op.Index = binary.LittleEndian.Uint32(buf[:])
	return nil
}

// writeOutPoint encodes op to the bitcoin protocol encoding for an OutPoint
// to w.
func writeOutPoint(w io.Writer, pver uint32, version int32, op *OutPoint) error {
	_, err := w.Write(op.Hash[:])
	if err != nil {
		return err
	}

	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], op.Index)
	_, err = w.Write(buf[:])
	if err != nil {
		return err
	}
	return nil
}

// readTxIn reads the next sequence of bytes from r as a transaction input
// (TxIn).
func readTxIn(r io.Reader, pver uint32, version int32, ti *TxIn) error {
	var op OutPoint
	err := readOutPoint(r, pver, version, &op)
	if err != nil {
		return err
	}
	ti.PreviousOutPoint = op

	ti.SignatureScript, err = ReadVarBytes(r, pver, MaxMessagePayload,
		"transaction input signature script")
	if err != nil {
		return err
	}

	var buf [4]byte
	_, err = io.ReadFull(r, buf[:])
	if err != nil {
		return err
	}
	ti.Sequence = binary.LittleEndian.Uint32(buf[:])

	return nil
}

// writeTxIn encodes ti to the bitcoin protocol encoding for a transaction
// input (TxIn) to w.
func writeTxIn(w io.Writer, pver uint32, version int32, ti *TxIn) error {
	err := writeOutPoint(w, pver, version, &ti.PreviousOutPoint)
	if err != nil {
		return err
	}

	err = WriteVarBytes(w, pver, ti.SignatureScript)
	if err != nil {
		return err
	}

	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], ti.Sequence)
	_, err = w.Write(buf[:])
	if err != nil {
		return err
	}

	return nil
}

// readTxOut reads the next sequence of bytes from r as a transaction output
// (TxOut).
func readTxOut(r io.Reader, pver uint32, version int32, to *TxOut) error {
	var buf [8]byte
	_, err := io.ReadFull(r, buf[:])
	if err != nil {
		return err
	}
	to.Value = int64(binary.LittleEndian.Uint64(buf[:]))

	to.PkScript, err = ReadVarBytes(r, pver, MaxMessagePayload,
		"transaction output public key script")
	if err != nil {
		return err
	}

	return nil
}

// writeTxOut encodes to into the bitcoin protocol encoding for a transaction
// output (TxOut) to w.
func writeTxOut(w io.Writer, pver uint32, version int32, to *TxOut) error {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(to.Value))
	_, err := w.Write(buf[:])
	if err != nil {
		return err
	}

	err = WriteVarBytes(w, pver, to.PkScript)
	if err != nil {
		return err
	}
	return nil
}
