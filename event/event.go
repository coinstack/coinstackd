// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package event

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/Jeffail/tunny"
)

const (
	queueSize = 200
)

var (
	currNode       string
	eventQueue     = make(chan Event, queueSize)
	eventListeners = make(map[string]map[eventListener]struct{})
	lock           sync.RWMutex
	pushTimeout    int32
	pool           *tunny.WorkPool
)

// Event define internal events
// most events may be defined in smart contracts
type Event struct {
	etype   string
	payload *json.RawMessage
}

type BlockEvent struct {
	blockhash []byte
	height    int
}

type TxEvent struct {
	txhash []byte
	sender []byte
}

type UDEvent struct {
	udetype string
	data    string
}

type eventResult struct {
	Etype string           `json:"UDEvent"`
	Data  *json.RawMessage `json:"data,omitempty"`
}

type eventListener string

func PushEvent(etype string, payload *json.RawMessage) {
	log.Tracef("Push Event %s %s", etype, payload)
	ee := Event{etype, payload}
	select {
	case eventQueue <- ee:
		log.Tracef("push event succeed")
	default:
		log.Tracef("push event failed(queue full)")
	}
}

func notifyEvent(etype string, data *json.RawMessage) {
	lock.RLock()

	listeners, ok := eventListeners[etype]
	if !ok {
		lock.RUnlock()
		return
	}

	targets := make([]eventListener, 0, len(listeners))
	for listener := range listeners {
		targets = append(targets, listener)
	}

	lock.RUnlock()

	for _, target := range targets {
		t := target
		pool.SendWorkAsync(func() {
			t.postEvent(etype, data)
		}, nil)
	}
}

func (listener *eventListener) postEvent(etype string, data *json.RawMessage) {
	logStr := fmt.Sprintf("Post Event %s %s %s", etype, string(*data), string(*listener))
	log.Trace(logStr)
	defer func() {
		log.Trace("End of ", logStr)
	}()
	er := eventResult{etype, data}
	jsonData, err := json.Marshal(er)
	if err != nil {
		return
	}
	buff := bytes.NewBuffer(jsonData)
	timeout := time.Duration(time.Duration(pushTimeout) * time.Second)
	client := http.Client{Timeout: timeout}
	resp, err := client.Post(string(*listener), "application/json;charset=utf-8", buff)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		log.Warnf("Notification failed: %v", err)
		return
	}
	ioutil.ReadAll(resp.Body)
}

func AddEventListener(etype, url, node string) bool {
	if etype == "" || url == "" {
		log.Tracef("Add EventListener - invalid argument value: event type(%s), url(%s)", etype, url)
		return false
	}
	if node != "" && node != currNode {
		log.Tracef("Add EventListener - mismatch node: current node(%s), node(%s)", currNode, node)
		return false
	}
	log.Tracef("Add EventListener: event type(%s), url(%s), nodeId(%s)", etype, url, node)

	lock.Lock()
	defer lock.Unlock()

	listeners, exists := eventListeners[etype]
	if !exists {
		listeners = make(map[eventListener]struct{})
		eventListeners[etype] = listeners
	}
	listener := eventListener(url)
	listeners[listener] = struct{}{}

	return true
}

func DeleteEventListener(etype string, url string) {
	log.Tracef("Delete EventListener: event type(%s), url(%s)", etype, url)

	lock.Lock()
	defer lock.Unlock()

	if listeners, exists := eventListeners[etype]; exists {
		listener := eventListener(url)
		delete(listeners, listener)
		if len(listeners) == 0 {
			delete(eventListeners, etype)
		}
	}
}

func DeleteEvent(etype string) []string {
	log.Tracef("Delete Event: event type(%s)", etype)

	lock.Lock()
	defer lock.Unlock()

	var urls []string
	if listeners, ok := eventListeners[etype]; ok {
		for listener := range listeners {
			urls = append(urls, string(listener))
		}
		delete(eventListeners, etype)
	}
	return urls
}

// handleNode handles node commands.
func handleChainEvent(elem Event) {
	switch elem.etype {
	case "block":
		//bc := BlockEvent{"xxx", "yyy"}
		notifyEvent("block", elem.payload)
	case "transaction":
		//tx := TxEvent{"xxx", "yyy"}
		notifyEvent("Tx", elem.payload)
	default:
		//ud := userDefined{"xxx", "yyy"}
		notifyEvent(elem.etype, elem.payload)
	}
}

func Handler(node string, timeout int32) {
	currNode = node
	pushTimeout = timeout
	for {
		ee := <-eventQueue
		log.Tracef("Event Pushed: %s", ee.etype)
		handleChainEvent(ee)
	}
}

func init() {
	pool, _ = tunny.CreatePoolGeneric(20).Open()
}
