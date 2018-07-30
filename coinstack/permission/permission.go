// Copyright (c) 2016 BLOCKO INC.
package permission

import (
	"strings"

	"github.com/coinstack/coinstackd/chaincfg"
	"github.com/coinstack/coinstackd/database"
)

// nolint: golint
const (
	AdminPermission  = "ADMIN"
	WriterPermission = "WRITER"
	MinerPermission  = "MINER"
	NodePermission   = "NODE"

	AdminMarker  byte = 1
	WriterMarker byte = 2
	MinerMarker  byte = 4
	NodeMarker   byte = 8

	AliasNameMaxSize   = 16
	AliasPublickeySize = 33
)

type Cmd uint8

// nolint: golint
const (
	EnablePermCmd Cmd = iota + 1
	SetPermCmd
	SetAliasCmd
)

type Marker struct {
	MajorVersion uint16
	MinorVersion uint16
	CmdType      Cmd
	Permission   byte

	Address   string
	Alias     string
	PublicKey []byte // 33 bytes
}

type Manager interface {
	CheckPermission(dbTx database.Tx, addr string, permission byte) bool
	IsPermissionEnabled(dbTx database.Tx, permission byte) bool
	GetParam() *chaincfg.Params
}

func ConvertToString(permissionByte byte) string {
	var strArray []string

	if (permissionByte & AdminMarker) == AdminMarker {
		strArray = append(strArray, AdminPermission)
	}
	if (permissionByte & WriterMarker) == WriterMarker {
		strArray = append(strArray, WriterPermission)
	}
	if (permissionByte & MinerMarker) == MinerMarker {
		strArray = append(strArray, MinerPermission)
	}
	if (permissionByte & NodeMarker) == NodeMarker {
		strArray = append(strArray, NodePermission)
	}

	return strings.Join(strArray, "|")
}
