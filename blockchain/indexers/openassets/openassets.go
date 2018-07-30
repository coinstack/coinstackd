// Copyright (c) 2016 BLOCKO INC.
package openassets

import (
	"bytes"
	"encoding/binary"

	"github.com/coinstack/leb128"
	"github.com/coinstack/coinstackd/txscript"
	"github.com/coinstack/coinstackd/wire"
	"github.com/coinstack/btcutil"
	"github.com/coinstack/btcutil/base58"
)

type Marker struct {
	MarkerIndex  int32
	MajorVersion uint16
	MinorVersion uint16
	Quantities   []uint64
}

type MetaType uint16

// nolint: golint
const (
	MetaUncolored MetaType = iota
	MetaMarker
	MetaIssuance
	MetaTransfer
)

type MetaInfo struct {
	Name       string
	UseAssetID bool
}

var MetaInfos = map[MetaType]MetaInfo{
	MetaUncolored: {"UNCOLORED", false},
	MetaMarker:    {"MARKER", false},
	MetaIssuance:  {"ISSUANCE", true},
	MetaTransfer:  {"TRANSFER", true},
}

type Meta struct {
	OutputType   MetaType // 2 bytes
	MajorVersion uint16   // 2 bytes
	MinorVersion uint16   // 2 bytes
	Quantity     uint64   // 8 bytes
	AssetID      []byte   // 20 bytes
	Script       []byte
}

func CalculateBase58(source []byte) string {
	return base58.CheckEncode(source, byte(23))
}

func calculateAssetID(baseScript []byte) ([]byte, error) {
	hashedScript := btcutil.Hash160(baseScript)
	return hashedScript, nil
}

func ParseMarkerOutput(markerOutput *wire.TxOut, markerIndex int32, outputCount int32) (*Marker, bool) {
	if len(markerOutput.PkScript) == 0 {
		log.Trace("marker output missing")
		return nil, false
	}
	markerScript := markerOutput.PkScript
	parsedScript, err := txscript.ParseScript(markerScript)

	if nil != err {
		return nil, false
	}

	if len(parsedScript) < 2 {
		log.Trace("failed to discover marker script")
		return nil, false
	}

	// check OP_RETURN
	if parsedScript[0].Opcode != "OP_RETURN" {
		log.Trace("failed to discover marker script")
		return nil, false
	}

	// check payload
	payload := parsedScript[1].Data
	payloadLength := len(payload)
	if payloadLength <= 4 {
		log.Trace("payload too short")
		return nil, false
	}

	// check marker magic
	if !bytes.HasPrefix(payload, []byte{0x4f, 0x41}) {
		log.Trace("magic byte not found")
		return nil, false
	}

	marker := Marker{}
	marker.MarkerIndex = markerIndex
	// extract version
	marker.MajorVersion = uint16(payload[2])
	marker.MinorVersion = uint16(payload[3])

	// extract quantities
	// get number of quantities
	numQuantities, numBytesRead := binary.Uvarint(payload[4:])

	// check quantity count
	if int32(numQuantities) > (outputCount - 1) {
		// output count mismatch
		log.Trace("output count mismatch")
		return nil, false
	}

	buffer := bytes.NewBuffer(payload[4+numBytesRead:])
	marker.Quantities = []uint64{}
	numQuantitiesExtracted := 0
	for i := 0; i < int(numQuantities); i++ {
		quantity, eof := leb128.ReadULeb128(buffer)
		if nil != eof {
			break
		}
		if i == int(marker.MarkerIndex) {
			marker.Quantities = append(marker.Quantities, 0)
		}
		marker.Quantities = append(marker.Quantities, quantity)
		numQuantitiesExtracted = numQuantitiesExtracted + 1
	}

	if int(numQuantitiesExtracted) != int(numQuantities) {
		log.Trace("leb128 quantity count mismatch")
		return nil, false
	}

	for i := int(numQuantities); i <= int(marker.MarkerIndex); i++ {
		marker.Quantities = append(marker.Quantities, 0)
	}

	return &marker, true
}

func AssignQuantities(tx *wire.MsgTx, inputMeta []*Meta, marker *Marker) ([]*Meta, bool) {
	if len(tx.TxOut) < len(marker.Quantities) {
		log.Trace("output count mismatched.")
		return nil, false
	}

	// prepare issurance
	var issuranceAssetID []byte
	if marker.MarkerIndex != 0 {
		var err error
		issuranceAssetID, err = calculateAssetID(inputMeta[0].Script)
		if err != nil {
			log.Trace("failed to calculated issuance asset id")
			return nil, false
		}
	}

	log.Trace("<inputs to be assigned>")
	for i, meta := range inputMeta {
		log.Tracef("[%v] %v (%v)", i, meta.Quantity, meta.AssetID)
	}

	log.Trace("<outputs to be assigned>")
	for i, quantity := range marker.Quantities {
		log.Tracef("[%v] %v", i, quantity)
	}

	numInputs := len(tx.TxIn)
	var inputIndex int
	remainingQuantity := inputMeta[inputIndex].Quantity
	currentAssetID := inputMeta[inputIndex].AssetID
	numQuantities := len(marker.Quantities)
	outputMeta := make([]*Meta, len(tx.TxOut))
	for i := range tx.TxOut {
		if nil == outputMeta[i] {
			outputMeta[i] = &Meta{}
		}

		if i < int(marker.MarkerIndex) {
			outputMeta[i].Quantity = marker.Quantities[i]
			if marker.Quantities[i] > 0 {
				outputMeta[i].OutputType = MetaIssuance
				outputMeta[i].AssetID = issuranceAssetID
			} else {
				outputMeta[i].OutputType = MetaUncolored
				outputMeta[i].AssetID = nil
			}
		} else if i == int(marker.MarkerIndex) {
			outputMeta[i].Quantity = marker.Quantities[i]
			outputMeta[i].OutputType = MetaMarker
			outputMeta[i].AssetID = nil
			outputMeta[i].MajorVersion = marker.MajorVersion
			outputMeta[i].MinorVersion = marker.MinorVersion
		} else if i >= numQuantities {
			outputMeta[i].OutputType = MetaUncolored
			outputMeta[i].AssetID = nil
			outputMeta[i].Quantity = 0
		} else {
			outputMeta[i].Quantity = marker.Quantities[i]
			if marker.Quantities[i] > 0 {
				log.Tracef("]output [%v] assigning input %v <- %v from [%v] %v", i, outputMeta[i].Quantity, remainingQuantity, inputIndex, currentAssetID)
				outputMeta[i].OutputType = MetaTransfer

				// examine input index
				if inputIndex == numInputs {
					log.Trace("input index out of bound")
					return nil, false
				}

				// fetch first none-zero input to assign assetId
				if remainingQuantity == 0 {
					for inputMeta[inputIndex].Quantity == 0 {
						inputIndex = inputIndex + 1
						if inputIndex == numInputs {
							log.Trace("input out of bound")
							return nil, false
						}
					}
					log.Tracef("current input %v", inputIndex)
					remainingQuantity = inputMeta[inputIndex].Quantity
				}
				outputMeta[i].AssetID = inputMeta[inputIndex].AssetID
				currentAssetID = inputMeta[inputIndex].AssetID
				log.Tracef("last asset id %v", currentAssetID)

				// assign asset id and shift input quantities
				if remainingQuantity > outputMeta[i].Quantity {
					log.Tracef(">output [%v] assigned input [%v] %v from %v", i, inputIndex, outputMeta[i].Quantity, remainingQuantity)
					log.Tracef("remaining quantity (%v for %v) enough, so keeping current input", remainingQuantity, outputMeta[i].Quantity)
					remainingQuantity = remainingQuantity - outputMeta[i].Quantity
				} else if remainingQuantity == outputMeta[i].Quantity {
					// find next none-zero input
					log.Tracef(">output [%v] assigned input [%v] %v from %v", i, inputIndex, outputMeta[i].Quantity, remainingQuantity)
					log.Tracef("remaining quantity (%v for %v) enough, so proceeding to next input", remainingQuantity, outputMeta[i].Quantity)
					currentAssetID = inputMeta[inputIndex].AssetID
					remainingQuantity = 0
					inputIndex = inputIndex + 1
				} else if remainingQuantity < outputMeta[i].Quantity {
					log.Tracef(">output [%v] assigned input [%v] %v from %v", i, inputIndex, remainingQuantity, inputMeta[inputIndex].Quantity)
					log.Tracef("remaining quantity not enough, so finding next input to assign")
					currentAssetID = inputMeta[inputIndex].AssetID
					var remainder = outputMeta[i].Quantity - remainingQuantity
					remainingQuantity = 0
					for inputMeta[inputIndex].Quantity == 0 || remainder > 0 {
						log.Tracef("resolving remainder %v", remainder)
						inputIndex = inputIndex + 1
						if inputIndex == numInputs {
							log.Trace("input index out of bound")
							return nil, false
						}
						if inputMeta[inputIndex].OutputType == MetaUncolored {
							continue
						}
						if !bytes.Equal(currentAssetID, inputMeta[inputIndex].AssetID) {
							log.Trace("asset id mismatched")
							return nil, false
						}

						if inputMeta[inputIndex].Quantity > remainder {
							log.Tracef(">>output [%v] assigned input [%v] %v from %v", i, inputIndex, remainder, inputMeta[inputIndex].Quantity)
							remainingQuantity = inputMeta[inputIndex].Quantity - remainder // quantities, shifting input
							break
						} else if inputMeta[inputIndex].Quantity == remainder {
							log.Tracef(">>output [%v] assigned input [%v] %v from %v", i, inputIndex, remainder, inputMeta[inputIndex].Quantity)
							remainingQuantity = 0 // used up all the quantities, shifting input
							inputIndex++
							break
						} else {
							log.Tracef(">>output [%v] assigned input [%v] %v from %v", i, inputIndex, inputMeta[inputIndex].Quantity, inputMeta[inputIndex].Quantity)
							remainder = remainder - inputMeta[inputIndex].Quantity
						}
					}
				}

			} else {
				outputMeta[i].OutputType = MetaUncolored
				outputMeta[i].AssetID = nil
			}
		}
	}
	return outputMeta, true
}
