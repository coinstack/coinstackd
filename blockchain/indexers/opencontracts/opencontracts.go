// Copyright (c) 2016 BLOCKO INC.
package opencontracts

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"

	"encoding/binary"
	"encoding/json"

	"github.com/coinstack/coinstackd/btcec"
	"github.com/coinstack/coinstackd/txscript"
	"github.com/coinstack/coinstackd/wire"
	"github.com/coinstack/btcutil"
	"github.com/vincent-petithory/dataurl"
)

type Marker struct {
	MajorVersion  uint16
	MinorVersion  uint16
	OpCode        OpCode
	PayloadHash   []byte // 32 bytes
	RawPayload    string
	PayloadScheme string
	PayloadData   []byte
	PayloadBody   Body
}

type Body struct {
	Type    string   `json:"type"`    // contract type. e.g. ESC (ethereum smart contract), LSC (lua smart contract)
	Version int      `json:"version"` // version of contract body. it's different with Crypto Version.
	Enc     int      `json:"enc"`     // is encrypted, 0:non-encrypted, 10:whole code encrypted, 20:parameters encrypted
	EEcks   []string `json:"eecks"`   // encrypted ECK array
	Body    []byte   `json:"body"`
}

type OpCode uint16

// nolint: golint
const (
	Issuance OpCode = iota
	Execution
	Termination
)

func ParseMarkerOutput(markerOutput *wire.TxOut) (*Marker, bool) {
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

	return parseMarkerPayload(parsedScript[1].Data)
}

func ParsePayloadBody(payloadBody []byte, body *Body) error {
	return json.Unmarshal(payloadBody, body)
}

func parseMarkerPayload(payload []byte) (*Marker, bool) {
	payloadLength := len(payload)
	if payloadLength <= 6 {
		log.Trace("payload too short")
		return nil, false
	}

	// check marker magic
	if !bytes.HasPrefix(payload, []byte{0x4f, 0x43}) { // stands for OC
		log.Trace("magic byte not found")
		return nil, false
	}

	marker := Marker{}
	// extract version
	marker.MajorVersion = uint16(payload[2])
	marker.MinorVersion = uint16(payload[3])

	// extract op code
	opLeft := uint16(payload[4])
	opRight := uint16(payload[5])
	if opLeft == 0 && opRight == 1 {
		if payloadLength <= 39 {
			log.Trace("payload too short")
			return nil, false
		}

		marker.OpCode = Issuance
		// get issuance context
	} else if opLeft == 0 && opRight == 2 {
		if payloadLength <= 39 {
			log.Trace("payload too short")
			return nil, false
		}

		marker.OpCode = Execution
	} else if opLeft == 0 && opRight == 3 {
		marker.OpCode = Termination
	} else {
		log.Trace("invalid opcode")
		return nil, false
	}

	marker.PayloadHash = payload[6:38]
	marker.RawPayload = string(payload[38:])

	if marker.MajorVersion == 1 || marker.MajorVersion == 2 {
		if marker.MinorVersion == 0 {
			payloadURL, err := url.Parse(marker.RawPayload)
			if nil != err {
				log.Trace("failed to parse payload")
				return nil, false
			}

			marker.PayloadScheme = payloadURL.Scheme
			if marker.PayloadScheme == "data" {
				dataURL, err := dataurl.DecodeString(marker.RawPayload)
				if nil != err {
					log.Trace("failed to parse dataurl")
					return nil, false
				}
				marker.PayloadData = dataURL.Data
			} else {
				log.Trace("Payload scheme not recognised")
				return nil, false
			}

		} else if marker.MinorVersion == 1 {
			marker.PayloadData = payload[38:]
		} else {
			log.Trace("Unknown contract version provided")
			return nil, false
		}
	} else {
		log.Trace("Unknown contract version provided")
		return nil, false
	}

	err := ParsePayloadBody(marker.PayloadData, &marker.PayloadBody)
	if nil != err {
		log.Trace("failed to parse contract body")
		return nil, false
	}
	return &marker, true
}

func FindECK(eecks []string, nodeWIF *btcutil.WIF, ver int) ([]byte, error) {
	if nodeWIF == nil {
		return nil, errors.New("cannot find ECK: no nodeWIF")
	}

	if eecks == nil || len(eecks) == 0 {
		return nil, errors.New("cannot find ECK: empty EECKs")
	}

	eeck, err := DecodesCompat(eecks[0], ver)
	if err != nil {
		return nil, err
	}

	// get an ephemeral public key
	secpubkey, err := btcec.ParsePubKey(eeck, btcec.S256())
	if err != nil {
		return nil, err
	}

	// calculate to get a password for eeck
	x, _ := secpubkey.Curve.ScalarMult(
		secpubkey.X, secpubkey.Y, nodeWIF.PrivKey.D.Bytes())
	log.Tracef("X=%v", x)
	log.Tracef("X.Text(16)=%v", x.Text(16))

	for i := 1; i < len(eecks); i++ {
		eeck, err := DecodesCompat(eecks[i], ver)
		if err != nil {
			return nil, err
		}
		// try to decrypt
		pbytes, err := DecryptsCompat(eeck, []byte(x.Text(16)), ver)
		if err == nil {
			return pbytes, nil
		}
	}
	return nil, errors.New("cannot find ECK")
}

func parseParameter(raw []byte) (uint16, uint16, uint32, string, error) {
	metaLen := 8
	if len(raw) < metaLen {
		return 0, 0, 0, "", errors.New("parsing fail: chunk size is short")
	}

	// parameter index
	paramIdx := binary.LittleEndian.Uint16(raw[0:])
	// parameter type (INT/LONG/DOUBLE/STRING)
	paramType := binary.LittleEndian.Uint16(raw[2:])
	// parameter value length
	paramValLen := binary.LittleEndian.Uint32(raw[4:])

	if len(raw[metaLen:]) < int(paramValLen) {
		log.Tracef("parameter: idx=%v, type=%v, valLen=%v, len(raw[8:])=%v",
			paramIdx, paramType, paramValLen, len(raw[metaLen:]))
		return 0, 0, 0, "", errors.New("parsing fail: value length is short")
	}

	// get parameter value
	paramVal := string(raw[metaLen : metaLen+int(paramValLen)])

	log.Tracef("parameter: idx=%v, type=%v, valLen=%v, val=%v",
		paramIdx, paramType, paramValLen, paramValLen)

	return paramIdx, paramType, paramValLen, paramVal, nil
}

func parseParameters(paramsCnt uint16, paramsChunk []byte, paramsArr []string) (int, error) {
	if paramsCnt == 0 || paramsChunk == nil {
		return 0, nil
	}

	paramsChunkLen := len(paramsChunk)
	log.Tracef("paramsCnt=%v, paramsChunk(%d)=%v, paramsArr=%v",
		paramsCnt, paramsChunkLen, paramsChunk, paramsArr)

	bytesIdx := 0
	for i := uint16(0); i < paramsCnt; i++ {
		if paramsChunkLen <= bytesIdx {
			return 0, errors.New("parameters chunk is short")
		}

		// parse parameter
		paramIdx, _, paramValLen, paramVal, err := parseParameter(paramsChunk[bytesIdx:])
		if err != nil {
			log.Debugf("fail to parse parameter[%v]: %v", i, err)
			return 0, fmt.Errorf("fail to parse parameter[%v]: %v", i, err)
		}
		paramsArr[paramIdx-1] = paramVal
		bytesIdx += 2 + 2 + 4 + int(paramValLen) // index(2) + type(2) + length(4) + value
	}
	return bytesIdx, nil
}

func parseEncryptedParameters(eparamsCnt uint16, eck, raw []byte, paramsArr []string, ver int) error {
	log.Debugf("parseEncryptedParameters: eparamsCnt=%v", eparamsCnt)

	if eparamsCnt <= 0 || eck == nil {
		log.Debugf("no encrypted chunk")
		return nil
	}

	eparamsChunkSize := binary.LittleEndian.Uint32(raw)
	log.Debugf("eparamsChunkSize=%v", eparamsChunkSize)

	bytesIdx := uint32(4)
	rawLen := int(bytesIdx + eparamsChunkSize)
	if len(raw) != rawLen {
		log.Debugf("rawLen=%v, len(raw)=%v", rawLen, len(raw))
		return errors.New("encrypted chunk is wrong: short raw chunk")
	}

	// decrypt encrypted parameters
	dparams, err := DecryptsCompat(raw[bytesIdx:rawLen], eck, ver)
	if err != nil {
		log.Debugf("fail to decrypt parameters: %v", err)
		return fmt.Errorf("fail to decrypt: %v", err)
	}

	if dparams == nil {
		return errors.New("encrypted chunk is wrong: no parameters")
	}

	readChunkSize, err := parseParameters(eparamsCnt, dparams, paramsArr)
	if err != nil {
		return err
	}
	log.Debugf("read chunk size = %v", readChunkSize)
	return err
}

func RegenContractCode(raw, eck []byte, ver int) (string, error) {
	log.Tracef("Raw len: %v", len(raw))
	bytesIdx := uint32(0)

	// read non-encrypted parameters number
	paramsCnt := binary.LittleEndian.Uint16(raw[bytesIdx:])
	log.Tracef("paramsCnt=%v", paramsCnt)
	bytesIdx += 2

	// read encrypted parameters number
	eparamsCnt := binary.LittleEndian.Uint16(raw[bytesIdx:])
	log.Tracef("eparamsCnt=%v", eparamsCnt)
	bytesIdx += 2

	// read code length
	codeLen := binary.LittleEndian.Uint32(raw[bytesIdx:])
	log.Tracef("Code length = %v", codeLen)
	bytesIdx += 4

	// read code
	code := string(raw[bytesIdx : bytesIdx+codeLen])
	log.Tracef("Code = %v", code)
	bytesIdx += codeLen

	// initialize buffer for parameters
	var paramsArr = make([]string, paramsCnt+eparamsCnt)
	if paramsCnt > 0 {
		// chunk size(4)
		paramsChunkSize := binary.LittleEndian.Uint32(raw[bytesIdx:])
		log.Tracef("paramsChunkSize=%v", paramsChunkSize)
		bytesIdx += 4

		readChunkSize, err := parseParameters(paramsCnt, raw[bytesIdx:], paramsArr)
		if err != nil {
			log.Debug(err)
		}
		if paramsChunkSize != uint32(readChunkSize) {
			return "", fmt.Errorf("parameters chunk is different: %v", readChunkSize)
		}
		bytesIdx += uint32(readChunkSize)
	}
	log.Tracef("bytesIdx = %v", bytesIdx)

	if eparamsCnt > 0 {
		err := parseEncryptedParameters(eparamsCnt, eck, raw[bytesIdx:], paramsArr, ver)
		if err != nil {
			// even though fail to decipher, code should be executed
			log.Debug(err)
		}
	}

	return regenerateCode(code, paramsArr), nil
}

func regenerateCode(code string, paramsArr []string) string {
	if paramsArr == nil || len(paramsArr) == 0 {
		return code
	}

	// regenerate code
	var codeBuf bytes.Buffer
	dquot := false
	squot := false
	paramIdx := 0
	for _, r := range code {
		if dquot {
			if r == '"' {
				dquot = false
			}
			codeBuf.WriteRune(r)
			continue
		}

		if squot {
			if r == '\'' {
				squot = false
			}
			codeBuf.WriteRune(r)
			continue
		}

		switch r {
		case '"':
			dquot = true
			codeBuf.WriteRune(r)
			break
		case '\'':
			squot = true
			codeBuf.WriteRune(r)
			break
		case '?':
			if paramsArr[paramIdx] == "" {
				codeBuf.WriteString("nil")
			} else {
				codeBuf.WriteString(paramsArr[paramIdx])
			}
			paramIdx++
			break
		default:
			codeBuf.WriteRune(r)
			break
		}
	}
	return codeBuf.String()
}
