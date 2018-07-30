// Copyright (c) 2016 BLOCKO INC.
package main

import (
	"context"
	"errors"
	"time"

	v3 "github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/clientv3/concurrency"
)

const minerLock = "MinerDlock"

var (
	ErrDlockLostOnInit = errors.New("Dlock(etcd mutex) lost on init")
)

type Dlock struct {
	*concurrency.Mutex
	*concurrency.Session
	*v3.Client
	ctx    context.Context
	cancel context.CancelFunc
}

// Return a new Dlock object from endpoints (comma seperated list of
// "ip:port").
// nolint: golint
func DlockNew(endpoints []string) (*Dlock, error) {
	minrLog.Debugf("MinerDlock creation started.")

	c, err := v3.New(v3.Config{
		Endpoints:   endpoints,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	// TODO: For liveness check, s.Done() can be used.
	s, err := concurrency.NewSession(c)
	if err != nil {
		return nil, err
	}

	// Create a mutex provided by the etcd's concurrency package.
	m := concurrency.NewMutex(s, minerLock)

	dlock := &Dlock{
		Mutex:   m,
		Session: s,
		Client:  c,
	}

	dlock.ctx, dlock.cancel = context.WithCancel(context.TODO())

	minrLog.Debugf("MinerDlock(lease=%x) return.", dlock.Session.Lease())

	return dlock, nil
}

// Acquire distributed lock.
func (dlock *Dlock) Acquire() error {
	err := dlock.Lock(dlock.ctx)
	if err != nil {
		return err
	}

	// The code below was taken from etcdctl ("lock" command code). For
	// some reason mutex may be lost after acquired.
	k, err := dlock.Get(dlock.ctx, dlock.Key())
	if err != nil {
		return err
	}
	if len(k.Kvs) == 0 {
		return ErrDlockLostOnInit
	}

	return nil
}

// Release distributed lock.
func (dlock *Dlock) Release() error {
	return dlock.Unlock(dlock.ctx)
}
