// Copyright (c) 2016 BLOCKO INC.
package ism

import (
	"errors"

	"github.com/bluele/gcache"
	"github.com/coinstack/gopher-lua"
)

type LStateCache struct {
	cache gcache.Cache
}

func NewLStateCache(size int) *LStateCache {
	log.Tracef("NewLStateCache: size=%d", size)
	cache := gcache.New(size).LRU().
		EvictedFunc(func(key, value interface{}) {
			if L, ok := value.(*lua.LState); ok {
				if L != nil {
					L.Close()
				}
			}
		}).
		PurgeVisitorFunc(func(key, value interface{}) {
			if L, ok := value.(*lua.LState); ok {
				if L != nil {
					L.Close()
				}
			}
		}).
		Build()
	return &LStateCache{cache}
}

func (lec *LStateCache) Put(key []byte, value *lua.LState) error {
	log.Tracef("LStateCache.Put: Key=%v, Value=%v", key, value)
	return lec.cache.Set(string(key), value)
}

func (lec *LStateCache) Get(key []byte) (*lua.LState, error) {
	value, err := lec.cache.Get(string(key))
	if err != nil {
		log.Tracef("LStateCache.Get: Key=%v is not found", key)
		return nil, err
	}
	log.Tracef("LStateCache.Get: Key=%v", key)
	if L, ok := value.(*lua.LState); ok {
		return L, nil
	}
	log.Tracef("invalid LState")
	return nil, errors.New("invalid LState")
}

func (lec *LStateCache) Remove(key []byte) {
	lec.cache.Remove(string(key))
}

func (lec *LStateCache) Purge() {
	lec.cache.Purge()
}
