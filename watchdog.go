// Copyright (c) 2016 BLOCKO INC.
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/coinstack/coinstackd/btcjson"
)

func getSyncPeerInfo(s *server) string {
	if s.blockManager.syncPeer == nil {
		return "No Sync Peer"
	}

	statsSnap := s.blockManager.syncPeer.StatsSnapshot()

	info := &btcjson.GetPeerInfoResult{
		ID:             statsSnap.ID,
		Addr:           statsSnap.Addr,
		Services:       fmt.Sprintf("%08d", uint64(statsSnap.Services)),
		LastSend:       statsSnap.LastSend.Unix(),
		LastRecv:       statsSnap.LastRecv.Unix(),
		ConnTime:       statsSnap.ConnTime.Unix(),
		PingTime:       float64(statsSnap.LastPingMicros),
		TimeOffset:     statsSnap.TimeOffset,
		Version:        statsSnap.Version,
		SubVer:         statsSnap.UserAgent,
		Inbound:        statsSnap.Inbound,
		StartingHeight: statsSnap.StartingHeight,
		CurrentHeight:  statsSnap.LastBlock,
		BanScore:       int32(s.blockManager.syncPeer.banScore.Int()),
	}

	jsonBytes, _ := json.Marshal(info)

	return string(jsonBytes)
}

func getMempoolInfo(s *server) string {

	mempoolTxns := s.txMemPool.TxDescs()
	var numBytes int64
	for _, txD := range mempoolTxns {
		numBytes += int64(txD.Tx.MsgTx().SerializeSize())
	}

	info := &btcjson.GetMempoolInfoResult{
		Size:  int64(len(mempoolTxns)),
		Bytes: numBytes,
	}

	jsonBytes, _ := json.Marshal(info)

	return string(jsonBytes)
}

func watchSync(s *server, messageDeadline time.Duration, blockDeadline time.Duration) {
	timer := time.NewTicker(time.Second * 1) // check every 60 seconds
	defer timer.Stop()
	var lastBlock string
	var lastHeight int32
	lastUpdated := time.Now()

	srvrLog.Infof("Starting watchdog")

	for {
		select {
		case <-timer.C:
			best := s.blockManager.chain.BestSnapshot()
			if best.Hash.String() != lastBlock {
				// update hash
				lastUpdated = time.Now()
				lastBlock = best.Hash.String()
				lastHeight = best.Height
			}

			if time.Since(lastUpdated).Seconds() > blockDeadline.Seconds() {
				srvrLog.Warnf("Disconnecting a sync peer due to block sync stall, last known block:%v at %v\n"+
					"  - Time since last block update %d seconds\n"+
					"  - Sync Peer Info = %s\n"+
					"  - Mempool Info = %s", lastBlock, lastHeight,
					int32(time.Since(s.blockManager.lastUpdated).Seconds()),
					getSyncPeerInfo(s), getMempoolInfo(s))

				if cfg.WatchdogDisconnectAll == true {
					// Disconnect all the peers on watchdog
					// expiration. This code is added to do
					// something even when there's no sync
					// peer. -- the old code in the else-if
					// block below doesn't do any thing
					// without a sync peer.
					//
					// This seems to resolve some block
					// sync failure although the exact
					// reason is not known.
					//
					// TODO: seek & destroy the casuse of
					// block sync failure.
					srvrLog.Debug("Watchdog send a diconnect-all message")
					s.cutAllPeers <- struct{}{}
				} else if s.blockManager.syncPeer != nil {
					// disconnect syncpeer to reset cached info
					s.blockManager.syncPeer.Disconnect()
				}
				// reset timer
				lastUpdated = time.Now()
			} else if time.Since(s.blockManager.lastUpdated).Seconds() > messageDeadline.Seconds() {
				srvrLog.Warnf("Disconnecting a all peers due to message stall, last updated message was at %v\n"+
					"  - Time since last peer message update %d seconds\n"+
					"  - Sync Peer Info = %s\n"+
					"  - Mempool Info = %s", s.blockManager.lastUpdated,
					int32(time.Since(s.blockManager.lastUpdated).Seconds()),
					getSyncPeerInfo(s), getMempoolInfo(s))

				// Last method, Shutting down server. has lots of problems,
				// especially re-syncing after netwrok recovery
				// So, we remove that and change to disconnect all the peers.
				//
				// TODO: collect and investgate message stall situations
				// and apply better way to handle that
				srvrLog.Debug("Watchdog send a diconnect-all message")
				s.cutAllPeers <- struct{}{}

				// reset timer
				lastUpdated = time.Now()
			}
		}
	}
}
