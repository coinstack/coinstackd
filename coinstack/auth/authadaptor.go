// Copyright (c) 2016 BLOCKO INC.
// Package auth comes from github.com/coinstack/coinstack-auth
// And this authadaptor.go file comes from authadaptor.go of coinstack-auth
package auth

import (
	"errors"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

const (
	defaultCacheSize       = 1024 * 512
	defaultCacheTTLSeconds = 60
)

type Adaptor interface {
	CheckSecretKey(string) (bool, string, string, error)
	CheckToken(string) (bool, string, error)
}

type MongoDBAdaptor struct {
	database string
	session  *mgo.Session
	cache    *lru.Cache
}

type KeyItem struct {
	UserID    string
	SecretKey string
	Fetched   time.Time
}

func OpenDB(url string, database string) (*MongoDBAdaptor, error) {
	session, err := mgo.Dial(url)
	if nil != err {
		return nil, errors.New("failed to open database")
	}

	cache, nil := lru.New(defaultCacheSize)
	return &MongoDBAdaptor{database, session, cache}, nil
}

func (db *MongoDBAdaptor) provisionDB() {
	session := db.session.Copy()
	defer session.Close()
	session.DB(db.database).DropDatabase()
}

func (db *MongoDBAdaptor) CloseDB() {
	db.session.Close()
}

func (db *MongoDBAdaptor) CheckSecretKey(apiKey string) (bool, string, string, error) {
	// check cache first
	cachedKey, ok := db.cache.Get(apiKey)
	if ok && time.Since(cachedKey.(*KeyItem).Fetched).Seconds() < defaultCacheTTLSeconds {
		return true, cachedKey.(*KeyItem).UserID, cachedKey.(*KeyItem).SecretKey, nil
	}

	// if cache not present or TTL over, fetch from DB
	session := db.session.Copy()
	defer session.Close()
	c := session.DB(db.database).C("apikeys")

	var key bson.M
	err := c.Find(bson.M{"_id": apiKey}).One(&key)
	if err != nil {
		if err == mgo.ErrNotFound {
			return false, "", "", nil
		}
		return false, "", "", errors.New("failed to fetch key from mongo")
	}
	var userID string
	userID, ok = key["userid"].(string)
	if !ok {
		return false, "", "", errors.New("failed to parse key from mongo")
	}
	secretKey, ok := key["secretkey"].(string)
	if !ok {
		return false, "", "", errors.New("failed to parse key from mongo")
	}
	// keep key in cache
	db.cache.Add(apiKey, &KeyItem{
		userID,
		secretKey,
		time.Now(),
	})

	return true, userID, secretKey, nil
}

func (db *MongoDBAdaptor) CheckToken(token string) (bool, string, error) {
	// check cache first
	cachedKey, ok := db.cache.Get(token)
	if ok && cachedKey.(*KeyItem).SecretKey == "" && time.Since(cachedKey.(*KeyItem).Fetched).Seconds() < defaultCacheTTLSeconds {
		return true, cachedKey.(*KeyItem).UserID, nil
	}

	// if cache not present or TTL over, fetch from DB
	session := db.session.Copy()
	defer session.Close()
	c := session.DB(db.database).C("apikeys")

	var key bson.M
	err := c.Find(bson.M{"_id": token}).One(&key)
	if nil != err {
		if err == mgo.ErrNotFound {
			return false, "", nil
		}
		return false, "", errors.New("failed to fetch key from mongo")
	}
	var userID string
	userID, ok = key["userid"].(string)
	if !ok {
		return false, "", errors.New("failed to parse key from mongo")
	}
	_, ok = key["secretkey"]
	if ok {
		return false, "", nil
	}
	// keep key in cache
	db.cache.Add(token, &KeyItem{
		userID,
		"",
		time.Now(),
	})

	return true, userID, nil
}
