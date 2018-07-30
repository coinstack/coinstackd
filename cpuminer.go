// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/coinstack/coinstackd/blockchain"
	"github.com/coinstack/coinstackd/btcjson"
	"github.com/coinstack/coinstackd/mining"
	"github.com/coinstack/coinstackd/txscript"
	"github.com/coinstack/coinstackd/wire"
	"github.com/coinstack/btcutil"
)

const (
	// maxNonce is the maximum value a nonce can be in a block header.
	maxNonce = ^uint32(0) // 2^32 - 1

	// maxExtraNonce is the maximum value an extra nonce used in a coinbase
	// transaction can be.
	maxExtraNonce = ^uint64(0) // 2^64 - 1

	// hashUpdateDuration is the duration to wait in between each
	// update to the hashes per second monitor.
	hashUpdateDuration = time.Millisecond * 10

	hashDisplayDuration = time.Second * 10

	// hashUpdateSec is the number of seconds each worker waits in between
	// notifying the speed monitor with how many hashes have been completed
	// while they are actively searching for a solution.  This is done to
	// reduce the amount of syncs between the workers that must be done to
	// keep track of the hashes per second.
	hashUpdateSecs = 15
)

var (
	// defaultNumWorkers is the default number of workers to use for mining
	// and is based on the number of processor cores.  This helps ensure the
	// system stays reasonably responsive under heavy load.
	defaultNumWorkers = uint32(runtime.NumCPU())
)

var errSignal = errors.New("received quit signal")

// CPUMiner provides facilities for solving blocks (mining) using the CPU in
// a concurrency-safe manner.  It consists of two main goroutines -- a speed
// monitor and a controller for worker goroutines which generate and solve
// blocks.  The number of goroutines can be set via the SetMaxGoRoutines
// function, but the default is based on the number of processor cores in the
// system which is typically sufficient.
type CPUMiner struct {
	sync.Mutex
	policy            *mining.Policy
	txSource          mining.TxSource
	server            *server
	numWorkers        uint32
	started           bool
	discreteMining    bool
	submitBlockLock   sync.Mutex
	wg                sync.WaitGroup
	workerWg          sync.WaitGroup
	updateNumWorkers  chan struct{}
	queryHashesPerSec chan float64
	updateHashes      chan uint64
	speedMonitorQuit  chan struct{}
	quit              chan struct{}
	hashesPerSec      float64
	lock              *Dlock
}

// speedMonitor handles tracking the number of hashes per second the mining
// process is performing.  It must be run as a goroutine.
func (m *CPUMiner) speedMonitor() {
	minrLog.Tracef("CPU miner speed monitor started")

	var totalHashes uint64
	ticker := time.NewTicker(hashUpdateDuration)
	defer ticker.Stop()

out:
	for {
		select {
		// Periodic updates from the workers with how many hashes they
		// have performed.
		case numHashes := <-m.updateHashes:
			totalHashes += numHashes

		// Time to update the hashes per second.
		case <-ticker.C:
			curHashesPerSec := float64(totalHashes) / hashUpdateDuration.Seconds()
			if m.hashesPerSec == 0 {
				m.hashesPerSec = curHashesPerSec
			}
			m.hashesPerSec = (m.hashesPerSec + curHashesPerSec) / 2
			totalHashes = 0

		// Request for the number of hashes per second.
		case m.queryHashesPerSec <- m.hashesPerSec:
			// Nothing to do.

		case <-m.speedMonitorQuit:
			break out
		}
	}

	m.wg.Done()
	minrLog.Tracef("CPU miner speed monitor done")
}

// submitBlock submits the passed block to network after ensuring it passes all
// of the consensus validation rules.
func (m *CPUMiner) submitBlock(block *btcutil.Block) bool {
	m.submitBlockLock.Lock()
	defer m.submitBlockLock.Unlock()

	// Ensure the block is not stale since a new block could have shown up
	// while the solution was being found.  Typically that condition is
	// detected and all work on the stale block is halted to start work on
	// a new block, but the check only happens periodically, so it is
	// possible a block was found and submitted in between.
	latestHash, _ := m.server.blockManager.chainState.Best()
	msgBlock := block.MsgBlock()
	if !msgBlock.Header.PrevBlock.IsEqual(latestHash) {
		minrLog.Debugf("Block submitted via CPU miner with previous "+
			"block %s is stale", msgBlock.Header.PrevBlock)
		return false
	}

	// Process this block using the same rules as blocks coming from other
	// nodes.  This will in turn relay it to the network like normal.
	bFlag := blockchain.BFNone
	if m.server.blockManager.fastAdd {
		bFlag = blockchain.BFFastAdd
	}
	isOrphan, err := m.server.blockManager.ProcessBlock(block, bFlag)
	if err != nil {
		// Anything other than a rule violation is an unexpected error,
		// so log that error as an internal error.
		if _, ok := err.(blockchain.RuleError); !ok {
			minrLog.Errorf("Unexpected error while processing "+
				"block submitted via CPU miner: %v", err)
			return false
		}

		minrLog.Debugf("Block submitted via CPU miner rejected: %v", err)
		return false
	}
	if isOrphan {
		minrLog.Debugf("Block submitted via CPU miner is an orphan")
		return false
	}

	// The block was accepted.
	coinbaseTx := block.MsgBlock().Transactions[0].TxOut[0]
	minrLog.Infof("Block submitted via CPU miner accepted (hash %s, "+
		"amount %v)", block.Sha(), btcutil.Amount(coinbaseTx.Value))
	return true
}

// solveBlock attempts to find some combination of a nonce, extra nonce, and
// current timestamp which makes the passed block hash to a value less than the
// target difficulty.  The timestamp is updated periodically and the passed
// block is modified with all tweaks during this process.  This means that
// when the function returns true, the block is ready for submission.
//
// This function will return early with false when conditions that trigger a
// stale block such as a new block showing up or periodically when there are
// new transactions and enough time has elapsed without finding a solution.
func (m *CPUMiner) solveBlock(msgBlock *wire.MsgBlock, blockHeight int32,
	ticker *time.Ticker, quit chan struct{}) bool {

	// Choose a random extra nonce offset for this block template and
	// worker.
	enOffset, err := wire.RandomUint64()
	if err != nil {
		minrLog.Errorf("Unexpected error while generating random "+
			"extra nonce offset: %v", err)
		enOffset = 0
	}

	// Create a couple of convenience variables.
	header := &msgBlock.Header
	targetDifficulty := blockchain.CompactToBig(header.Bits)

	// Initial state.
	lastGenerated := time.Now()
	lastTxUpdate := m.txSource.LastUpdated()
	hashesCompleted := uint64(0)

	// ticker to use for throttling
	throttlingTicker := time.NewTicker(hashUpdateDuration)
	defer throttlingTicker.Stop()
	var totalThrottlingHashes uint64
	lastThrottleTime := time.Now()

	displayTicker := time.NewTicker(hashDisplayDuration)
	defer displayTicker.Stop()

	// Note that the entire extra nonce range is iterated and the offset is
	// added relying on the fact that overflow will wrap around 0 as
	// provided by the Go spec.
	for extraNonce := uint64(0); extraNonce < maxExtraNonce; extraNonce++ {
		// Update the extra nonce in the block template with the
		// new value by regenerating the coinbase script and
		// setting the merkle root to the new value.  The
		UpdateExtraNonce(msgBlock, blockHeight, extraNonce+enOffset) // nolint: errcheck

		// Include miner signature for private network
		if cfg.PrivateNet && cfg.PrivateNetNodeKey != "" {
			coinbaseTx := msgBlock.Transactions[0]

			signature, pubkeyHash, err := blockchain.CalculateBlockSignature(cfg.PrivateNetNodeKey, msgBlock.Header.MerkleRoot.Bytes())
			if err != nil {
				minrLog.Debugf("Failed to sign block with miner key")
				return false
			}

			payScript, err := txscript.NewScriptBuilder().AddData(pubkeyHash).Script()
			if err != nil {
				minrLog.Debugf("Failed to sign block with miner key")
				return false
			}
			coinbaseTx.AddTxOut(&wire.TxOut{
				Value:    0,
				PkScript: payScript,
			})

			dataScript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN).AddData(signature).Script()
			if err != nil {
				minrLog.Debugf("Failed to sign block with miner key")
				return false
			}
			coinbaseTx.AddTxOut(&wire.TxOut{
				Value:    0,
				PkScript: dataScript,
			})

			// Update merkleeroot
			block := btcutil.NewBlock(msgBlock)
			merkles := blockchain.BuildMerkleTreeStore(block.Transactions())
			msgBlock.Header.MerkleRoot = *merkles[len(merkles)-1]
		}

		// Search through the entire nonce range for a solution while
		// periodically checking for early quit and stale block
		// conditions along with updates to the speed monitor.
		for i := uint32(0); i <= maxNonce; i++ {
			select {
			case <-quit:
				return false

			case <-ticker.C:
				m.updateHashes <- hashesCompleted
				hashesCompleted = 0

				// The current block is stale if the best block
				// has changed.
				bestHash, _ := m.server.blockManager.chainState.Best()
				if !header.PrevBlock.IsEqual(bestHash) {
					return false
				}

				// The current block is stale if the memory pool
				// has been updated since the block template was
				// generated and it has been at least one
				// minute.
				if lastTxUpdate != m.txSource.LastUpdated() &&
					time.Now().After(lastGenerated.Add(time.Minute)) {

					return false
				}

				UpdateBlockTime(msgBlock, m.server.blockManager) // nolint: errcheck
			case <-throttlingTicker.C:
				curHashesPerSec := float64(totalThrottlingHashes) / (time.Since(lastThrottleTime).Seconds())
				if curHashesPerSec == 0 {
					break
				}
				if cfg.MaxHashrate == 0 {
					break // max hashrate of 0 indicates no throttling (default)
				}
				targetHashRate := cfg.MaxHashrate
				if uint32(curHashesPerSec) > targetHashRate {
					// sleep for a bit
					time.Sleep(hashUpdateDuration)
				} else {
					lastThrottleTime = time.Now()
					totalThrottlingHashes = 0
				}

			case <-displayTicker.C:
				curHashesPerSec := float64(totalThrottlingHashes) / (time.Since(lastThrottleTime).Seconds())
				if curHashesPerSec != 0 {
					minrLog.Debugf("Hash speed: %6.0f hashes/s",
						curHashesPerSec)
				}
			default:
				// Non-blocking select to fall through
			}

			// Update the nonce and hash the block header.  Each
			// hash is actually a double sha256 (two hashes), so
			// increment the number of hashes completed for each
			// attempt accordingly.
			header.Nonce = i
			hash := header.BlockSha()
			hashesCompleted += 2
			totalThrottlingHashes += 2

			// The block is solved when the new block hash is less
			// than the target difficulty.  Yay!
			if blockchain.ShaHashToBig(&hash).Cmp(targetDifficulty) <= 0 {
				m.updateHashes <- hashesCompleted
				return true
			}
		}
	}

	return false
}

func chkQuit(quit chan struct{}) error {
	// For graceful shutdown
	select {
	case <-quit:
		minrLog.Debugf("MinerDlock: Received a graceful shutdown notification.")
		return errSignal
	default:
		return nil
	}
}

func (m *CPUMiner) setDistLock(ep []string, quit chan struct{}) error {
	minrLog.Debugf("CoordEndpoint: %v", ep)

	if m.lock != nil {
		return nil
	}

	for {
		lock, err := DlockNew(ep)
		if err != nil {
			minrLog.Infof("MinerDlock creation failed: %s", err.Error())
		} else if lock == nil {
			minrLog.Infof("MinerDlock creation failed: null")
		} else {
			go func(lock *Dlock, quit chan struct{}) {
				select {
				case <-quit:
					// For gracefull shutdown
					lock.cancel()
				case <-lock.Session.Done():
					// To prevent go-routine leak
					return
				}
			}(lock, quit)

			m.lock = lock
			return nil
		}
		if err = chkQuit(quit); err != nil {
			return err
		}
		time.Sleep(10)
	}
}

func (m *CPUMiner) unsetDistLock() {
	err := m.lock.Release()
	if err != nil {
		minrLog.Debugf("MinerDlock release failed: %s", err.Error())
	} else {
		minrLog.Debugf("MinerDlock released.")
	}
	err = m.lock.Client.Close()
	if err != nil {
		minrLog.Debugf("MinerDlock client close failed: %s", err.Error())
	} else {
		minrLog.Debugf("MinerDlock client closed.")
	}
	err = m.lock.Session.Close()
	if err != nil {
		minrLog.Debugf("MinerDlock session close failed: %s", err.Error())
	} else {
		minrLog.Debugf("MinerDlock session closed")
	}
	m.lock = nil
}

func (m *CPUMiner) distLock(quit chan struct{}) error {
	nFail := uint32(0)
	for {
		err := m.setDistLock(cfg.CoordMiningEndpoint, quit)
		// Error returns only upon an OS signal.
		if err != nil {
			return err
		}

		err = m.lock.Acquire()
		if err == context.Canceled {
			minrLog.Debugf("MinerDlock: canceled")
			return err
		} else if err != nil {
			if (nFail % 60) == 0 { // To prevent exessive logging
				minrLog.Infof("Retry (%d) MinerDlock acquisition: %s", nFail, err.Error())
			}
			m.unsetDistLock()

			nFail++
			time.Sleep(10 * time.Second)

			minrLog.Debugf("Retry MinerDlock acquisition: %s", err.Error())
		} else {
			minrLog.Debugf("MinerDlock acquired")
			return nil
		}
	}
}

func (m *CPUMiner) distUnlock() {
	if m.lock == nil {
		return
	}
	m.lock.Release() // nolint: errcheck
	m.lock = nil
}

// func (m *CPUMiner) distLockOk() bool {
// 	return m.lock.CheckOk()
// }

func (m *CPUMiner) generateBlocksDone() {
	m.workerWg.Done()
	minrLog.Tracef("Generate blocks worker done")
}

func coordMiningOn() bool {
	return len(cfg.CoordMiningEndpoint) > 0
}

func capOn() bool {
	return len(cfg.CAPEndpoint) > 0
}

func genCmd(block *btcutil.Block) ([]byte, error) {
	rawBlock, err := block.Bytes()
	if err != nil {
		return nil, err
	}

	cmd := btcjson.NewSubmitBlockCmd(hex.EncodeToString(rawBlock), nil)

	marshalledJSON, err := btcjson.MarshalCmd(1, cmd)
	if err != nil {
		return nil, err
	}

	return marshalledJSON, nil
}

func sendRPC(rawJSON []byte, url, user, passwd string) (resp *http.Response, err error) {
	bodyReader := bytes.NewReader(rawJSON)

	req, err := http.NewRequest("POST", url, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Close = true
	req.Header.Set("Content-Type", "application/json")

	req.SetBasicAuth(user, passwd)

	client := new(http.Client)
	resp, err = client.Do(req)
	if err != nil {
		return resp, err
	}
	return resp, nil
}

func recvResponse(resp *http.Response) error {
	respBytes, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if len(respBytes) == 0 {
			return fmt.Errorf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
		}
		return errors.New(string(respBytes))
	}

	var result btcjson.Response
	if err := json.Unmarshal(respBytes, &result); err != nil {
		return err
	}

	if result.Error != nil {
		return result.Error
	}

	return nil
}

func doRPC(rawJSON []byte, url, user, passwd string) (err error) {

	resp, err := sendRPC(rawJSON, url, user, passwd)
	if err != nil {
		return err
	}

	return recvResponse(resp)
}

func getError(errChan <-chan error, epNum int, strict bool) (err error) {
	errCount := 0
	for i := int(0); i < epNum; i++ {
		select {
		case err = <-errChan:
			if err != nil {
				errCount++
			}
		}
	}

	// In the strict mode, even one error is not allowed.
	if (strict && errCount > 0) || errCount == epNum {
		return
	}

	return nil
}

func execCmd(cmd []byte, ep []string, user string, passwd string, strict bool) error {
	epNum := len(ep)
	errChan := make(chan error, epNum)
	for i := 0; i < epNum; i++ {
		// Using go-routines, concurrently send the command to the CAP
		// peers. TODO: make go-routines on boot to reduce the create
		// overhead.
		go func(addr string) {
			ec := doRPC(cmd, "http://"+addr, user, passwd)
			if ec != nil {
				minrLog.Infof("CAP propagation (to %s) failed - %s", addr, ec.Error())
			}
			errChan <- ec
		}(ep[i])
	}

	// If any of the submits succeeds, it is regarded as success.
	return getError(errChan, epNum, strict)
}

func propagateBlock(block *btcutil.Block, ep []string, user string, passwd string) (err error) {
	cmd, err := genCmd(block)
	if err != nil {
		return
	}

	err = execCmd(cmd, ep, user, passwd, cfg.CAPStrict)

	return
}

type poormanMining struct {
	lastAwaken time.Time
}

func (pm *poormanMining) wait(defaultTimeWait uint32) <-chan time.Time {
	nextAwaken := pm.lastAwaken.Add(time.Duration(defaultTimeWait) * time.Second)
	now := time.Now()
	waitTime := nextAwaken.Sub(now)

	if waitTime < 0 {
		minrLog.Debugf("Interval exceeded by %fs. Mining will begin immediately.",
			float64(-waitTime)/float64(time.Second))
		waitTime = 0
	} else {
		minrLog.Debugf("Mining will start after %fs",
			float64(waitTime)/float64(time.Second))
	}

	return time.After(waitTime)
}

func (pm *poormanMining) update() {
	pm.lastAwaken = time.Now()
}

// generateBlocks is a worker that is controlled by the miningWorkerController.
// It is self contained in that it creates block templates and attempts to solve
// them while detecting when it is performing stale work and reacting
// accordingly by generating a new block template.  When a block is solved, it
// is submitted.
//
// It must be run as a goroutine.
func (m *CPUMiner) generateBlocks(quit chan struct{}) {
	minrLog.Tracef("Starting generate blocks worker")

	// Start a ticker which is used to signal checks for stale work and
	// updates to the speed monitor.
	ticker := time.NewTicker(hashUpdateDuration)
	defer ticker.Stop()

	pm := poormanMining{lastAwaken: time.Now()}
out:
	for {
		// Quit when the miner is stopped.
		select {
		case <-quit:
			break out
		default:
			// Non-blocking select to fall through
		}
		// Wait until there is a connection to at least one other peer
		// since there is no way to relay a found block or receive
		// transactions to work on when there are no connected peers.
		if m.server.ConnectedCount() == 0 && activeNetParams.Net != wire.PrivNet {
			minrLog.Tracef("no peer connected")
			time.Sleep(time.Second)
			continue
		}

		// Acuire distLock everytime for safety
		if coordMiningOn() {
			if err := m.distLock(quit); err != nil {
				m.distUnlock()
				if err == context.Canceled || err == errSignal {
					break out
				}
				continue
			}
		}

		// No point in searching for a solution before the chain is
		// synced.  Also, grab the same lock as used for block
		// submission, since the current block will be changing and
		// this would otherwise end up building a new block template on
		// a block that is in the process of becoming stale.
		m.submitBlockLock.Lock()
		_, curHeight := m.server.blockManager.chainState.Best()
		if curHeight != 0 && !m.server.blockManager.IsCurrent() {
			m.submitBlockLock.Unlock()
			time.Sleep(time.Second)
			continue
		}

		if activeNetParams.Net == wire.PrivNet {
			// private network
			if cfg.PrivateNetSetupBlocks >= uint32(curHeight+1) {
				// in setup phase
				if !cfg.PrivateNetBootstrapping {
					m.submitBlockLock.Unlock()
					minrLog.Tracef("waiting for bootstrapping node")
					time.Sleep(time.Second)
					continue
				}
			} else if cfg.PrivateNetMiningInterval > 0 {
				m.submitBlockLock.Unlock()
				select {
				case <-pm.wait(cfg.PrivateNetMiningInterval):
					pm.update()
					minrLog.Debug("Interval Mining Begin")
				case <-quit:
					break out
				}
				m.submitBlockLock.Lock()
			} else {
				if m.server.ConnectedCount() == 0 && !cfg.PrivateNetPeerlessMining {
					// past setup phase
					m.submitBlockLock.Unlock()
					minrLog.Tracef("no peer connected")
					time.Sleep(time.Second)
					continue
				}
			}
		}

		// Choose a payment address at random.
		rand.Seed(time.Now().UnixNano())
		payToAddr := cfg.miningAddrs[rand.Intn(len(cfg.miningAddrs))]

		// Create a new block template using the available transactions
		// in the memory pool as a source of transactions to potentially
		// include in the block.
		template, err := NewBlockTemplate(m.policy, m.server, payToAddr)
		m.submitBlockLock.Unlock()
		if err != nil {
			errStr := fmt.Sprintf("Failed to create new block "+
				"template: %v", err)
			minrLog.Errorf(errStr)
			continue
		}

		// Attempt to solve the block.  The function will exit early
		// with false when conditions that trigger a stale block, so
		// a new block template can be generated.  When the return is
		// true a solution was found, so submit the solved block.
		if m.solveBlock(template.Block, curHeight+1, ticker, quit) {
			block := btcutil.NewBlock(template.Block)
			if capOn() {
				err := propagateBlock(block, cfg.CAPEndpoint, cfg.CAPUser, cfg.CAPPass)
				if err != nil {
					minrLog.Infof("Block dropped due to failed propagation: %s", err.Error())
					continue
				}
			}

			m.submitBlock(block)
		}
	}

	m.generateBlocksDone()
}

// miningWorkerController launches the worker goroutines that are used to
// generate block templates and solve them.  It also provides the ability to
// dynamically adjust the number of running worker goroutines.
//
// It must be run as a goroutine.
func (m *CPUMiner) miningWorkerController() {
	// launchWorkers groups common code to launch a specified number of
	// workers for generating blocks.
	var runningWorkers []chan struct{}
	launchWorkers := func(numWorkers uint32) {
		for i := uint32(0); i < numWorkers; i++ {
			quit := make(chan struct{})
			runningWorkers = append(runningWorkers, quit)

			m.workerWg.Add(1)
			go m.generateBlocks(quit)
		}
	}

	// Launch the current number of workers by default.
	runningWorkers = make([]chan struct{}, 0, m.numWorkers)
	launchWorkers(m.numWorkers)

out:
	for {
		select {
		// Update the number of running workers.
		case <-m.updateNumWorkers:
			// No change.
			numRunning := uint32(len(runningWorkers))
			if m.numWorkers == numRunning {
				continue
			}

			// Add new workers.
			if m.numWorkers > numRunning {
				launchWorkers(m.numWorkers - numRunning)
				continue
			}

			// Signal the most recently created goroutines to exit.
			for i := numRunning - 1; i >= m.numWorkers; i-- {
				close(runningWorkers[i])
				runningWorkers[i] = nil
				runningWorkers = runningWorkers[:i]
			}

		case <-m.quit:
			for _, quit := range runningWorkers {
				close(quit)
			}
			break out
		}
	}

	// Wait until all workers shut down to stop the speed monitor since
	// they rely on being able to send updates to it.
	m.workerWg.Wait()
	close(m.speedMonitorQuit)
	m.wg.Done()
}

// Start begins the CPU mining process as well as the speed monitor used to
// track hashing metrics.  Calling this function when the CPU miner has
// already been started will have no effect.
//
// This function is safe for concurrent access.
func (m *CPUMiner) Start() {
	m.Lock()
	defer m.Unlock()

	// Nothing to do if the miner is already running or if running in discrete
	// mode (using GenerateNBlocks).
	if m.started || m.discreteMining {
		return
	}

	m.quit = make(chan struct{})
	m.speedMonitorQuit = make(chan struct{})
	m.wg.Add(2)
	go m.speedMonitor()
	go m.miningWorkerController()

	m.started = true
	minrLog.Infof("CPU miner started")
}

// Stop gracefully stops the mining process by signalling all workers, and the
// speed monitor to quit.  Calling this function when the CPU miner has not
// already been started will have no effect.
//
// This function is safe for concurrent access.
func (m *CPUMiner) Stop() {
	m.Lock()
	defer m.Unlock()

	// Nothing to do if the miner is not currently running or if running in
	// discrete mode (using GenerateNBlocks).
	if !m.started || m.discreteMining {
		return
	}

	close(m.quit)
	m.wg.Wait()
	m.started = false
	minrLog.Infof("CPU miner stopped")
}

// IsMining returns whether or not the CPU miner has been started and is
// therefore currenting mining.
//
// This function is safe for concurrent access.
func (m *CPUMiner) IsMining() bool {
	m.Lock()
	defer m.Unlock()

	return m.started
}

// HashesPerSecond returns the number of hashes per second the mining process
// is performing.  0 is returned if the miner is not currently running.
//
// This function is safe for concurrent access.
func (m *CPUMiner) HashesPerSecond() float64 {
	m.Lock()
	defer m.Unlock()

	// Nothing to do if the miner is not currently running.
	if !m.started {
		return 0
	}

	return <-m.queryHashesPerSec
}

// SetNumWorkers sets the number of workers to create which solve blocks.  Any
// negative values will cause a default number of workers to be used which is
// based on the number of processor cores in the system.  A value of 0 will
// cause all CPU mining to be stopped.
//
// This function is safe for concurrent access.
func (m *CPUMiner) SetNumWorkers(numWorkers int32) {
	if numWorkers == 0 {
		m.Stop()
	}

	// Don't lock until after the first check since Stop does its own
	// locking.
	m.Lock()
	defer m.Unlock()

	if len(cfg.CoordMiningEndpoint) > 0 || cfg.PrivateNetMiningInterval > 0 {
		// m.numWorkers is forced to be set to *one* in the cases
		// below:
		//
		// 1. Coordinated Mining: with cfg.NumMiners > 1 it ends up
		//    with erratic behaviors, one of which is seg. fault caused
		//    by race condition (the code assumes single miner
		//    go-routine).
		//
		// 2. Interval Mining (cfg.PrivateNetMiningInterval > 0):
		//    there's no benefit to use cfg.NumMiners > 0 because
		//    interval mining *unconditionally* applies the lowest
		//    difficulty.
		m.numWorkers = 1
	} else if numWorkers < 0 {
		// Use default if provided value is negative.
		m.numWorkers = defaultNumWorkers
	} else {
		m.numWorkers = uint32(numWorkers)
	}

	// When the miner is already running, notify the controller about the
	// the change.
	if m.started {
		m.updateNumWorkers <- struct{}{}
	}
}

// NumWorkers returns the number of workers which are running to solve blocks.
//
// This function is safe for concurrent access.
func (m *CPUMiner) NumWorkers() int32 {
	m.Lock()
	defer m.Unlock()

	return int32(m.numWorkers)
}

// GenerateNBlocks generates the requested number of blocks. It is self
// contained in that it creates block templates and attempts to solve them while
// detecting when it is performing stale work and reacting accordingly by
// generating a new block template.  When a block is solved, it is submitted.
// The function returns a list of the hashes of generated blocks.
func (m *CPUMiner) GenerateNBlocks(n uint32) ([]*wire.ShaHash, error) {
	m.Lock()

	// Respond with an error if there's virtually 0 chance of CPU-mining a block.
	if !m.server.chainParams.GenerateSupported {
		m.Unlock()
		return nil, errors.New("No support for `generate` on the current " +
			"network, " + m.server.chainParams.Net.String() +
			", as it's unlikely to be possible to CPU-mine a block.")
	}

	// Respond with an error if server is already mining.
	if m.started || m.discreteMining {
		m.Unlock()
		return nil, errors.New("Server is already CPU mining. Please call " +
			"`setgenerate 0` before calling discrete `generate` commands.")
	}

	m.started = true
	m.discreteMining = true

	m.speedMonitorQuit = make(chan struct{})
	m.wg.Add(1)
	go m.speedMonitor()

	m.Unlock()

	minrLog.Tracef("Generating %d blocks", n)

	i := uint32(0)
	blockHashes := make([]*wire.ShaHash, n, n)

	// Start a ticker which is used to signal checks for stale work and
	// updates to the speed monitor.
	ticker := time.NewTicker(time.Second * hashUpdateSecs)
	defer ticker.Stop()

	for {
		// Read updateNumWorkers in case someone tries a `setgenerate` while
		// we're generating. We can ignore it as the `generate` RPC call only
		// uses 1 worker.
		select {
		case <-m.updateNumWorkers:
		default:
		}

		// Grab the lock used for block submission, since the current block will
		// be changing and this would otherwise end up building a new block
		// template on a block that is in the process of becoming stale.
		m.submitBlockLock.Lock()
		_, curHeight := m.server.blockManager.chainState.Best()

		// Choose a payment address at random.
		rand.Seed(time.Now().UnixNano())
		payToAddr := cfg.miningAddrs[rand.Intn(len(cfg.miningAddrs))]

		// Create a new block template using the available transactions
		// in the memory pool as a source of transactions to potentially
		// include in the block.
		template, err := NewBlockTemplate(m.policy, m.server, payToAddr)
		m.submitBlockLock.Unlock()
		if err != nil {
			errStr := fmt.Sprintf("Failed to create new block "+
				"template: %v", err)
			minrLog.Errorf(errStr)
			continue
		}

		// Attempt to solve the block.  The function will exit early
		// with false when conditions that trigger a stale block, so
		// a new block template can be generated.  When the return is
		// true a solution was found, so submit the solved block.
		if m.solveBlock(template.Block, curHeight+1, ticker, nil) {
			block := btcutil.NewBlock(template.Block)
			m.submitBlock(block)
			blockHashes[i] = block.Sha()
			i++
			if i == n {
				minrLog.Tracef("Generated %d blocks", i)
				m.Lock()
				close(m.speedMonitorQuit)
				m.wg.Wait()
				m.started = false
				m.discreteMining = false
				m.Unlock()
				return blockHashes, nil
			}
		}
	}
}

// newCPUMiner returns a new instance of a CPU miner for the provided server.
// Use Start to begin the mining process.  See the documentation for CPUMiner
// type for more details.
func newCPUMiner(policy *mining.Policy, s *server) *CPUMiner {
	return &CPUMiner{
		policy:            policy,
		txSource:          s.txMemPool,
		server:            s,
		numWorkers:        defaultNumWorkers,
		updateNumWorkers:  make(chan struct{}),
		queryHashesPerSec: make(chan float64),
		updateHashes:      make(chan uint64),
	}
}
