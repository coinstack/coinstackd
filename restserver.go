// Copyright (c) 2016 BLOCKO INC.
// Package coinstack comes from github.com/coinstack/coinstack-core
// And this handler.go file comes from core/handler.go of coinstack-core
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/http/pprof"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin/binding"

	hmacauth "github.com/coinstack/go-hmacauth"
	"github.com/coinstack/coinstackd/blockchain"
	"github.com/coinstack/coinstackd/blockchain/indexers"
	"github.com/coinstack/coinstackd/blockchain/indexers/openassets"
	"github.com/coinstack/coinstackd/chaincfg"
	"github.com/coinstack/coinstackd/coinstack"
	auth "github.com/coinstack/coinstackd/coinstack/auth"
	"github.com/coinstack/coinstackd/coinstack/client"
	"github.com/coinstack/coinstackd/coinstack/sync"
	"github.com/coinstack/coinstackd/database"
	"github.com/coinstack/coinstackd/txscript"
	"github.com/coinstack/coinstackd/wire"
	"github.com/coinstack/btcutil"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
	psnet "github.com/shirou/gopsutil/net"
)

const (
	errNoNextBlock            = "no next block"
	errNotExistBlockHeight    = "failed to obtain block height"
	errDeserializeBlock       = "failed to deserialize block"
	errDeserializeBlockHeader = "failed to deserialize block header"
	errDeserializeTx          = "failed to deserialize transaction"
)

type CoinstackHandle struct {
	auth            auth.Adaptor
	enableAuth      bool
	db              *CoinstackAdaptor
	syncEndpoint    string
	monitorEndpoint string
	stamperEndpoint string
}

type CoinstackHandleConfig struct {
	Auth            auth.Adaptor
	MonitorEndpoint string
	StamperEndpoint string
}

func NewCoinstackHandle(db *CoinstackAdaptor, config CoinstackHandleConfig) *CoinstackHandle {
	return &CoinstackHandle{auth: config.Auth, enableAuth: config.Auth != nil, db: db, monitorEndpoint: config.MonitorEndpoint, stamperEndpoint: config.StamperEndpoint}
}

func createGin() *gin.Engine {
	// r := martini.NewRouter()
	m := gin.New()

	// 로그 관련 설정
	// m.DisableConsoleColor()

	m.Use(gin.Recovery())
	// m.Use(martini.Recovery())
	// m.MapTo(r, (*martini.Routes)(nil))
	// m.Action(r.Handle)
	return m
}

func (handler *CoinstackHandle) HandleREST() {
	// REST API
	m := createGin()
	m.Use(cors.New(cors.Config{
		AllowAllOrigins: true,
		AllowMethods:    []string{"GET", "POST"},
		AllowHeaders:    []string{"Authorization", "Content-Type", "Accept"},
	}))

	// auth middleware
	options := hmacauth.Options{
		SignedHeaders: []string{"Content-MD5", "Content-Type"},
		SecretKey: hmacauth.KeyLocator(func(apiKey string) (string, string) {
			ok, user, secretKey, err := handler.auth.CheckSecretKey(apiKey)
			if !ok || nil != err {
				if nil != err {
					restLog.Errorf("Failed to access auth db: %v", err)
				}
				return "", ""
			}

			return user, secretKey
		}),
		SignatureExpiresIn: 15 * time.Minute,
	}
	hmacAuth := hmacauth.HMACAuth(options)
	apiKeyAuth := func(res http.ResponseWriter, req *http.Request) bool {
		// check for APIKey SecretKey header
		if req.Header.Get("APIKey") == "" {
			return false
		}

		// if present, auth using them
		ok, user, err := handler.auth.CheckToken(req.Header.Get("APIKey"))
		if nil != err {
			res.WriteHeader(http.StatusInternalServerError)
			return true
		}
		if !ok {
			res.WriteHeader(http.StatusUnauthorized)
			return true
		}

		// auth successful
		req.Header.Add("User", user)
		return true
	}
	m.Use(func(c *gin.Context) {
		req := c.Request
		res := c.Writer

		// skip check if auth disabled
		if !handler.enableAuth {
			return
		}
		// skip check for root
		if "/" == req.RequestURI || "" == req.RequestURI {
			return
		}

		// inject authorization header if absent and there is param
		values := req.URL.Query()
		if paramAuth := values.Get("auth"); paramAuth != "" {
			req.Header.Set("Authorization", paramAuth)
		}
		if paramAPIKey := values.Get("apikey"); paramAPIKey != "" {
			req.Header.Set("APIKey", paramAPIKey)
		}

		if paramMD5 := values.Get("md5"); paramMD5 != "" {
			req.Header.Set("Content-MD5", paramMD5)
		}

		if paramContentType := values.Get("content-type"); paramContentType != "" {
			req.Header.Set("Content-Type", paramContentType)
		}

		// examine using API key and secret key
		if apiKeyAuth(res, req) {
			return
		}

		// run hmacAuth otherwise
		hmacAuth(res, req)
	})

	m.GET("/", func(c *gin.Context) {
		c.String(200, "CoinStack Core")
	})
	m.GET("/blockchain", func(c *gin.Context) {
		status, err := handler.db.FetchBlockchainStatus()
		if nil != err {
			restLog.Errorf("%v", err)
			coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
			c.JSON(coinstackErr.Status(), coinstackErr)
			return
		} else {
			c.JSON(200, status)
		}
	})

	m.GET("/blocks/:blockhash/:p2", func(c *gin.Context) {
		blockhash := c.Param("blockhash")
		p2 := c.Param("p2")

		if blockhash == "height" {
			handler.DoGetBlockByHeight(c, p2)
			return
		}
		if p2 != "transactions" {
			coinstackErr := client.NewCoinStackError(client.ResourceNotFound).SetCause("not found")
			c.JSON(coinstackErr.Status(), coinstackErr)
			return
		}
		txs, err := handler.db.FetchBlockTransactions(blockhash)
		if nil != err {
			coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
			c.JSON(coinstackErr.Status(), coinstackErr)
			return
		}
		c.JSON(200, txs)
	})

	m.GET("/blocks/:blockhash", func(c *gin.Context) {
		format := c.Request.URL.Query().Get("format")
		block, ok, err := handler.db.FetchBlock(c.Param("blockhash"), format)
		if nil != err {
			coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
			c.JSON(coinstackErr.Status(), coinstackErr)
			return
		}
		if !ok {
			coinstackErr := client.NewCoinStackError(client.ResourceNotFound).SetCause("Requested block not found.")
			c.JSON(coinstackErr.Status(), coinstackErr)
			return
		}

		rw := c.Writer
		if b, ok := block.([]byte); ok {
			msg := hex.EncodeToString(b)
			rw.Header().Set("Content-Type", "text/plain")
			rw.WriteHeader(200)
			rw.Write([]byte(msg)) // nolint: errcheck
			return
		}
		cblock := block.(*client.Block)
		c.JSON(200, cblock)
	})

	// m.GET("/blocks/height/:blockheight", func(c *gin.Context) {
	// 	blockHeight, err := strconv.Atoi(c.Param("blockheight"))
	// 	if err != nil {
	// 		coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
	// 		c.JSON(coinstackErr.Status(), coinstackErr)
	// 		return
	// 	}
	// 	ids, err := handler.db.FetchBlockHeight(blockHeight)
	// 	if err != nil {
	// 		coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
	// 		c.JSON(coinstackErr.Status(), coinstackErr)
	// 		return
	// 	}
	// 	if len(ids) == 0 {
	// 		coinstackErr := client.NewCoinStackError(client.ResourceNotFound).SetCause("Requested transaction not found.")
	// 		c.JSON(coinstackErr.Status(), coinstackErr)
	// 		return
	// 	}
	// 	c.JSON(200, ids)
	// })

	m.GET("/transactions/:txhash", func(c *gin.Context) {
		req := c.Request
		format := req.URL.Query().Get("format")
		tx, ok, err := handler.db.FetchTransaction(c.Param("txhash"), format)
		if nil != err {
			coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
			c.JSON(coinstackErr.Status(), coinstackErr)
			return
		}
		if !ok {
			coinstackErr := client.NewCoinStackError(client.ResourceNotFound).SetCause("Requested transaction not found.")
			c.JSON(coinstackErr.Status(), coinstackErr)
			return
		}

		rw := c.Writer
		if b, ok := tx.([]byte); ok {
			msg := hex.EncodeToString(b)
			rw.Header().Set("Content-Type", "text/plain")
			rw.WriteHeader(200)
			rw.Write([]byte(msg)) // nolint: errcheck
			return
		}
		ctx := tx.(*client.Transaction)
		c.JSON(200, ctx)
	})

	m.GET("/addresses/:address/history", func(c *gin.Context) {
		req := c.Request
		skip := req.URL.Query().Get("skip")
		limit := req.URL.Query().Get("limit")
		confirmed := req.URL.Query().Get("confirmed")
		skipCount, skipCountErr := strconv.Atoi(skip)
		limitCount, limitCountErr := strconv.Atoi(limit)
		confirmedFilter, confirmedFilterErr := strconv.Atoi(confirmed)
		if nil != skipCountErr {
			skipCount = 0
		}
		if nil != limitCountErr {
			limitCount = -1
		}
		if nil != confirmedFilterErr {
			confirmedFilter = -1
		}

		var txs []string
		var err error
		if skipCountErr != nil && limitCountErr != nil && confirmedFilterErr != nil {
			txs, err = handler.db.FetchTransactionHistory(c.Param("address"))
		} else {
			txs, err = handler.db.FetchTransactionHistoryPaged(c.Param("address"), skipCount, limitCount, confirmedFilter)
		}
		if nil != err {
			coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
			c.JSON(coinstackErr.Status(), coinstackErr)
			return
		}
		c.JSON(200, txs)
	})

	m.GET("/addresses/:address/balance", func(c *gin.Context) {
		balance, err := handler.db.FetchBalance(c.Param("address"))
		if nil != err {
			coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
			c.JSON(coinstackErr.Status(), coinstackErr)
			return
		}
		c.JSON(200, map[string]interface{}{"balance": balance})
	})

	m.GET("/addresses/:address/unspentoutputs", func(c *gin.Context) {
		amount := c.Request.URL.Query().Get("amount")
		amountSatoshi := 0
		if s, err := strconv.Atoi(amount); err == nil {
			amountSatoshi = s
		}
		uxtos, err := handler.db.FetchUnspentOutputs(c.Param("address"), int64(amountSatoshi))
		if nil != err {
			coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
			c.JSON(coinstackErr.Status(), coinstackErr)
			return
		}
		c.JSON(200, uxtos)
	})

	// reverse proxy for other services
	// TODO: move to a seperate service
	// sync API
	if handler.db.SupportsTxBroadcast() {
		m.POST("/transactions", // binding.Json(client.PushTxRequest{}),
			func(c *gin.Context) {
				var txRequest client.PushTxRequest
				if err := c.ShouldBindWith(&txRequest, binding.JSON); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}
				err := handler.db.PushTransaction(txRequest.Tx)
				if nil != err {
					switch err := err.(type) {
					case sync.IllegalTxError:
						coinstackErr := client.NewCoinStackError(client.ValidationFailed).SetCause(err.Cause)
						c.JSON(coinstackErr.Status(), coinstackErr)
					case sync.DuplicateTxError:
						coinstackErr := client.NewCoinStackError(client.ValidationFailed).SetCause("Transaction already submitted")
						c.JSON(coinstackErr.Status(), coinstackErr)
					default:
						restLog.Errorf("Internal server error: %v", err)
						coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
						c.JSON(coinstackErr.Status(), coinstackErr)
					}

					return
				}
				c.JSON(200, map[string]interface{}{"status": "successful"})
			})
	} else {
		m.POST("/transactions",
			func(c *gin.Context) {
				target, err := url.Parse(handler.syncEndpoint)
				if nil != err {
					restLog.Criticalf("failed to parse sync endpoint url: %s", handler.syncEndpoint)
				}
				proxy := httputil.NewSingleHostReverseProxy(target)
				transport := coinstack.ErrorHandlingRoundTripper{}
				proxy.Transport = &transport
				proxy.ServeHTTP(c.Writer, c.Request)
			})
	}

	// smart contract API
	m.GET("/contracts/:address/status",
		func(c *gin.Context) {
			contractStatus, ok, err := handler.db.FetchContractStatus(c.Param("address"))
			if nil != err {
				coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
				c.JSON(coinstackErr.Status(), coinstackErr)
				return
			}
			if !ok {
				coinstackErr := client.NewCoinStackError(client.ResourceNotFound).SetCause("Requested contract not found.")
				c.JSON(coinstackErr.Status(), coinstackErr)
				return
			}
			c.JSON(200, contractStatus)
		})

	m.POST("/contracts/:address/query", // binding.Json(client.ContractQuery{}),
		func(c *gin.Context) {
			var queryRequest client.ContractQuery
			if err := c.ShouldBindWith(&queryRequest, binding.JSON); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			contractResult, ok, err := handler.db.QueryContract(c.Param("address"), queryRequest.Query)
			if nil != err {
				restLog.Errorf("Internal server error: %v", err)
				coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
				c.JSON(coinstackErr.Status(), coinstackErr)
				return
			}
			if !ok {
				coinstackErr := client.NewCoinStackError(client.ResourceNotFound).SetCause("Requested contract not found.")
				c.JSON(coinstackErr.Status(), coinstackErr)
				return
			}
			c.JSON(200, contractResult)
		})
	m.GET("/contracts/:address/grantees",
		func(c *gin.Context) {
			permissions := handler.db.FetchContractGrantees(c.Param("address"))
			c.JSON(200, permissions)
		})
	m.GET("/contracts/:address/source",
		func(c *gin.Context) {
			req := c.Request
			contentType := req.Header.Get("Content-Type")
			source, err := handler.db.FetchContractSource(c.Param("address"))
			if err != nil {
				var coinstackErr *client.CoinStackError
				if err == indexers.ErrNoContractFound {
					coinstackErr = client.NewCoinStackError(client.ResourceNotFound).SetCause(err.Error())
				} else {
					restLog.Errorf("Internal server error: %v", err)
					coinstackErr = client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
				}
				if contentType == "application/json" {
					c.JSON(coinstackErr.Status(), coinstackErr)
				} else {
					c.String(coinstackErr.Status(), coinstackErr.String())
				}
				return
			}
			if contentType == "application/json" {
				c.JSON(200, source)
			} else {
				c.String(200, source)
			}
		})
	m.GET("/contracts/:address/functions",
		func(c *gin.Context) {
			req := c.Request
			contentType := req.Header.Get("Content-Type")
			fns, err := handler.db.FetchContractFnSigs(c.Param("address"))
			if err != nil {
				var coinstackErr *client.CoinStackError
				if err == indexers.ErrNoContractFound {
					coinstackErr = client.NewCoinStackError(client.ResourceNotFound).SetCause(err.Error())
				} else {
					restLog.Errorf("Internal server error: %v", err)
					coinstackErr = client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
				}
				if contentType == "application/json" {
					c.JSON(coinstackErr.Status(), coinstackErr)
				} else {
					c.String(coinstackErr.Status(), coinstackErr.String())
				}
				return
			}
			if contentType == "application/json" {
				c.JSON(200, fns)
			} else {
				c.String(200, client.ContractFnSigs(fns).String())
			}
		})
	m.GET("/contracts/:address", func(c *gin.Context) {
		if "nodegroupkey" != c.Param("address") {
			coinstackErr := client.NewCoinStackError(client.ResourceNotFound).SetCause("not found")
			c.JSON(coinstackErr.Status(), coinstackErr)
			return
		}
		pubkeybytes, _, err := handler.db.GetBytes("NodeGroupPubKeyBytes")
		if nil != err {
			restLog.Error(err)
			coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
			c.JSON(coinstackErr.Status(), coinstackErr)
			return
		}
		c.JSON(200, map[string]interface{}{"pubkey": pubkeybytes})
	})

	// stamper API
	m.POST("/stamps", func(c *gin.Context) {
		// check throttling
		// FIXME: temp bypass for block accounts
		// FIXME: check acount based quota
		// if req.Header.Get("User") != "yc39eDQ4GhwkaFSfc" { // shepelt
		// 	// check quota
		// 	stat, _ := scribe.FetchDailyStat(req.Header.Get("User"), scribe.POST_STAMP)
		// 	if stat > 128 {
		// 		// over quota!
		// 		coinstackErr := client.NewCoinStackError(client.ThroughputExceeded).SetCause("Stamping quota exceeded over daily limit of 128.")
		// 		c.JSON(coinstackErr.Status(), coinstackErr)
		// 		return
		// 	}
		// }

		target, err := url.Parse(handler.stamperEndpoint)
		if nil != err {
			restLog.Criticalf("failed to parse stamp endpoint url: %s", handler.stamperEndpoint)
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		transport := coinstack.ErrorHandlingRoundTripper{}
		proxy.Transport = &transport
		proxy.ServeHTTP(c.Writer, c.Request)
	})
	m.GET("/stamps/:id",
		func(c *gin.Context) {
			target, err := url.Parse(handler.stamperEndpoint)
			if nil != err {
				restLog.Criticalf("failed to parse stamp endpoint url: %s", handler.stamperEndpoint)
			}
			proxy := httputil.NewSingleHostReverseProxy(target)
			transport := coinstack.ErrorHandlingRoundTripper{}
			proxy.Transport = &transport
			proxy.ServeHTTP(c.Writer, c.Request)
		})

	m.GET("/aliases/:aliasName", func(c *gin.Context) {
		if handler.db.SupportsPermission() {
			publickey := handler.db.FetchPublickey(c.Param("aliasName"))

			c.JSON(200, publickey)
		} else {
			coinStackErr := client.NewCoinStackError(client.ServerUnavailable).SetCause("Permission is not supported. Set privnetnodekey to use permission.")
			c.JSON(coinStackErr.Status(), coinStackErr)
		}
	})

	m.GET("/aliases", func(c *gin.Context) {
		if handler.db.SupportsPermission() {
			publickeyMap, err := handler.db.FetchAllPublickeys()

			if nil != err {
				restLog.Errorf("Internal server error: %v", err)
				coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
				c.JSON(coinstackErr.Status(), coinstackErr)
				return
			}

			c.JSON(200, publickeyMap)
		} else {
			coinStackErr := client.NewCoinStackError(client.ServerUnavailable).SetCause("Permission is not supported. Set privnetnodekey to use permission.")
			c.JSON(coinStackErr.Status(), coinStackErr)
		}
	})

	m.GET("/roles", func(c *gin.Context) {
		if handler.db.SupportsPermission() {
			permissionMap, err := handler.db.FetchAllPermissions()

			if nil != err {
				restLog.Errorf("Internal server error: %v", err)
				coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
				c.JSON(coinstackErr.Status(), coinstackErr)
				return
			}

			c.JSON(200, permissionMap)
		} else {
			coinStackErr := client.NewCoinStackError(client.ServerUnavailable).SetCause("Permission is not supported. Set privnetnodekey to use permission.")
			c.JSON(coinStackErr.Status(), coinStackErr)
		}
	})

	m.GET("/roles/:address", func(c *gin.Context) {
		address := c.Param("address")
		if "enabled" == address {
			if handler.db.SupportsPermission() {
				permission := handler.db.FetchEnabledPermissions()

				c.JSON(200, permission)
			} else {
				coinStackErr := client.NewCoinStackError(client.ServerUnavailable).SetCause("Permission is not supported. Set privnetnodekey to use permission.")
				c.JSON(coinStackErr.Status(), coinStackErr)
			}
		} else {
			if handler.db.SupportsPermission() {
				permission := handler.db.FetchPermission(address)

				c.JSON(200, permission)
			} else {
				coinStackErr := client.NewCoinStackError(client.ServerUnavailable).SetCause("Permission is not supported. Set privnetnodekey to use permission.")
				c.JSON(coinStackErr.Status(), coinStackErr)
			}
		}
	})

	// debug APIs
	if handler.db.EnableDebug() {
		m.GET("/debug", func(c *gin.Context) {
			description := []string{"/debug/mempool",
				"/debug/mempool/list",
				"/debug/mempool/orphanlist",
				"/debug/mempool/dump",
				"/debug/blockmanager",
				"/debug/metric/disk",
				"/debug/metric/network",
				"/debug/metric?net={ethernet_name}\u0026disk={disk_name}",
				"/debug/contracts",
				"/debug/pprof",
				"/debug/pprof/trace?seconds={time_to_profile}",
			}
			c.JSON(200, description)
		})

		m.GET("/debug/mempool", func(c *gin.Context) {
			info := handler.db.GetMempoolStatus()
			c.JSON(200, info)
		})

		m.GET("/debug/mempool/list", func(c *gin.Context) {
			orphanTxList, err := handler.db.GetMempoolTxList()
			if nil != err {
				coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
				c.JSON(coinstackErr.Status(), coinstackErr)
				return
			}
			c.JSON(200, orphanTxList)
		})

		m.GET("/debug/mempool/orphanlist", func(c *gin.Context) {
			orphanTxList, err := handler.db.GetOrphanTxList()
			if nil != err {
				coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
				c.JSON(coinstackErr.Status(), coinstackErr)
				return
			}
			c.JSON(200, orphanTxList)
		})

		m.GET("/debug/mempool/dump", func(c *gin.Context) {
			size := handler.db.DumpAllMemTx()
			c.JSON(200, size)
		})

		m.GET("/debug/blockmanager", func(c *gin.Context) {
			dataMap := handler.db.GetBlockManagerDebugInfo()

			c.JSON(200, dataMap)
		})

		m.GET("/debug/metric/disk", func(c *gin.Context) {
			ioCounter, err := disk.IOCounters()
			if err != nil {
				restLog.Errorf("Internal server error: %v", err.Error())
				coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
				c.JSON(coinstackErr.Status(), coinstackErr)
			}
			c.JSON(200, ioCounter)
		})

		m.GET("/debug/metric/network", func(c *gin.Context) {
			netInterfaces, err := psnet.IOCounters(true)
			if err != nil {
				restLog.Errorf("Internal server error: %v", err.Error())
				coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
				c.JSON(coinstackErr.Status(), coinstackErr)
			}
			c.JSON(200, netInterfaces)
		})

		m.GET("/debug/metric", func(c *gin.Context) {
			memory, err := mem.VirtualMemory()
			if err != nil {
				restLog.Errorf("Internal server error: %v", err.Error())
				coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
				c.JSON(coinstackErr.Status(), coinstackErr)
			}
			cp, err := cpu.Percent(0, false)
			if err != nil {
				restLog.Errorf("Internal server error: %v", err.Error())
				coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
				c.JSON(coinstackErr.Status(), coinstackErr)
			}
			currentTime := time.Now().Unix()
			result := fmt.Sprintf("TIME: %v WRITE: %v READ: %v CPU: %.0f MEM: %.0f",
				currentTime, handler.db.FetchWriteCounter(), handler.db.FetchReadCounter(), cp[0], memory.UsedPercent)

			query := c.Request.URL.Query()
			if query.Get("net") != "" {
				netInterfaces, err := psnet.IOCounters(true)
				if err != nil {
					restLog.Errorf("Internal server error: %v", err.Error())
					coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
					c.JSON(coinstackErr.Status(), coinstackErr)
				}
				findInterface := false
				for _, netI := range netInterfaces {
					if strings.Compare(netI.Name, query.Get("net")) == 0 {
						result = fmt.Sprintf("%s NETIN: %d NETOUT: %d", result, netI.BytesRecv, netI.BytesSent)
						findInterface = true
					}
				}
				if !findInterface {
					result = fmt.Sprintf("%s NoSuchNet", result)
				}
			}

			if query.Get("disk") != "" {
				ioCounter, err := disk.IOCounters()
				if err != nil {
					restLog.Errorf("Internal server error: %v", err.Error())
					coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
					c.JSON(coinstackErr.Status(), coinstackErr)
				}
				ioStat := ioCounter[query.Get("disk")]
				empty := disk.IOCountersStat{}
				if ioStat != empty {
					result = fmt.Sprintf("%s READ: %d WRITE: %d", result, ioStat.ReadBytes, ioStat.WriteBytes)
				} else {
					result = fmt.Sprintf("%s NoSuchDisk", result)
				}
			}

			c.JSON(200, result)
		})

		m.GET("/debug/contracts",
			func(c *gin.Context) {
				stat := handler.db.FetchContractStats()
				c.JSON(200, stat)
			})

		m.GET("/debug/pprof", func(c *gin.Context) {
			pprof.Index(c.Writer, c.Request)
			return
		})
		m.GET("/debug/pprof/cmdline", func(c *gin.Context) {
			pprof.Cmdline(c.Writer, c.Request)
			return
		})
		m.GET("/debug/pprof/profile", func(c *gin.Context) {
			pprof.Profile(c.Writer, c.Request)
			return
		})
		m.GET("/debug/pprof/symbol", func(c *gin.Context) {
			pprof.Symbol(c.Writer, c.Request)
			return
		})
		m.POST("/debug/pprof/symbol", func(c *gin.Context) {
			pprof.Symbol(c.Writer, c.Request)
			return
		})
		m.GET("/debug/pprof/block", func(c *gin.Context) {
			pprof.Handler("block").ServeHTTP(c.Writer, c.Request)
			return
		})
		m.GET("/debug/pprof/heap", func(c *gin.Context) {
			pprof.Handler("heap").ServeHTTP(c.Writer, c.Request)
			return
		})
		m.GET("/debug/pprof/goroutine", func(c *gin.Context) {
			pprof.Handler("goroutine").ServeHTTP(c.Writer, c.Request)
			return
		})
		m.GET("/debug/pprof/threadcreate", func(c *gin.Context) {
			pprof.Handler("threadcreate").ServeHTTP(c.Writer, c.Request)
			return
		})
		m.GET("/debug/pprof/trace", func(c *gin.Context) {
			pprof.Trace(c.Writer, c.Request)
			return
		})
	}

	// provide keyvalue storage for shinhan project
	if handler.db.EnableKVStore() {
		var kvMap map[string]int
		kvMap = make(map[string]int)

		/*
			(GET) /kvstore - get all stored key-value pairs
			(GET) /kvstore/:key - get a stored value in a key
			(POST) /kvstore/set/:key/:value - set a given value to a key
			(POST) /kvstore/plus/:key/:value - plus a given value to an existing value
			(POST) /kvstore/minus/:key/:value - minus a given value to an existing value
			(POST) /kvstore/multiply/:key/:value - multiply a given value to an existing value
			(POST) /kvstore/divide/:key/:value - divide a given value to an existing value
			(POST) /kvstore/reset - clear all data
		*/
		m.GET("/kvstore", func(c *gin.Context) {
			c.JSON(200, kvMap)
		})

		m.GET("/kvstore/:key", func(c *gin.Context) {
			key := c.Param("key")
			c.JSON(200, kvMap[key])
		})

		m.POST("/kvstore/:op/:key/:value", func(c *gin.Context) {
			op := c.Param("op")
			key := c.Param("key")
			strvalue := c.Param("value")

			intvalue, err := strconv.Atoi(strvalue)
			if err != nil {
				coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
				c.JSON(coinstackErr.Status(), coinstackErr)
				return
			}

			switch op {
			case "set":
				kvMap[key] = intvalue
				break
			case "plus":
				kvMap[key] = kvMap[key] + intvalue
				break
			case "minus":
				kvMap[key] = kvMap[key] - intvalue
				break
			case "multiply":
				kvMap[key] = kvMap[key] * intvalue
				break
			case "divide":
				if intvalue == 0 {
					c.JSON(400, "Try to divide by zero")
					return
				}
				kvMap[key] = kvMap[key] / intvalue
				break
			default:
				c.JSON(400, "Unsupported key-value storage operator")
				return
			}

			c.JSON(200, kvMap[key])
		})

		m.POST("/kvstore/:op", func(c *gin.Context) {
			op := c.Param("op")
			switch op {
			case "reset":
				kvMap = make(map[string]int)
				c.JSON(200, "ok")
				return
			default:
				c.JSON(400, "Unsupported key-value storage operator")
				return
			}
		})
	}

	m.GET("/sock",
		func(c *gin.Context) {
			// make websocket connection
			ws, err := websocket.Upgrade(c.Writer, c.Request, nil, 1024, 1024)
			if _, ok := err.(websocket.HandshakeError); ok {
				http.Error(c.Writer, "Not a websocket handshake", 400)
				return
			} else if err != nil {
				restLog.Critical(err)
				return
			}

			var inputJSON WebsocketInput

			for {
				err := ws.ReadJSON(&inputJSON)
				if err != nil {
					// ignore normal case
					if websocket.IsCloseError(err, websocket.CloseNormalClosure) {
						return
					}
					restLog.Errorf("%v", err)
					return
				}

				resultjson := ProcessWebsocket(handler.db, inputJSON)

				//response message
				if err := ws.WriteJSON(resultjson); err != nil {
					restLog.Errorf("%v", err)
					return
				}
			}
		})

	type writePayload struct {
		messageType int
		data        []byte
	}

	// websocket
	m.GET("/websocket", func(c *gin.Context) {
		if handler.db.SupportsWebsocket() {
			w := c.Writer
			req := c.Request

			ws, err := websocket.Upgrade(w, req, nil, 1024, 1024)
			if _, ok := err.(websocket.HandshakeError); ok {
				http.Error(w, "Not a websocket handshake", 400)
				return
			} else if err != nil {
				restLog.Errorf("%v", err)
				return
			}

			writeChan := make(chan *writePayload)
			// add events
			var blockEvent client.BlockEvent
			blockEvent = func(block *client.Block) {
				data, err := json.Marshal(block)
				if nil != err {
					restLog.Errorf("failed to marshal block: %v", err)
					return
				}
				writeChan <- &writePayload{
					client.BlockMessage,
					data,
				}
			}
			var txEvent client.TxEvent
			txEvent = func(tx *client.Transaction) {
				data, err := json.Marshal(tx)
				if nil != err {
					restLog.Errorf("failed to marshal tx: %v", err)
					return
				}
				writeChan <- &writePayload{
					client.TxMessage,
					data,
				}
			}

			handler.db.AddBlockHandler(&blockEvent)
			defer handler.db.RemoveBlockHandler(&blockEvent)
			handler.db.AddTxHandler(&txEvent)
			defer handler.db.RemoveTxHandler(&txEvent)

			runPong := true
			go func() {
				for runPong {
					restLog.Debug("reading msg")
					messagetype, data, err := ws.ReadMessage()
					if nil != err {
						restLog.Errorf("failed to read: %v", err)
						return
					}

					switch messagetype {
					case client.PingMessage:
						restLog.Debugf("ping received %s", string(data))
						writeChan <- &writePayload{
							client.PongMessage,
							[]byte("{}"),
						}
					default:
						restLog.Debugf("msg received: type: %d", messagetype)
					}
				}
			}()
			for {
				data := <-writeChan
				rawData := json.RawMessage(data.data)
				payload := client.WebSocketPayload{
					Type:    data.messageType,
					Payload: &rawData,
				}

				rawPayload, err := json.Marshal(payload)
				if nil != err {
					restLog.Errorf("failed to marshal payload: %v", err)
					continue
				}
				err = ws.WriteMessage(websocket.BinaryMessage, rawPayload)
				if nil != err {
					restLog.Errorf("write failed, discarding socket: %v", err)
					runPong = false
					ws.Close()
					return
				}
			}
		} else {
			coinstackErr := client.NewCoinStackError(client.ServerUnavailable)
			c.JSON(coinstackErr.Status(), coinstackErr)
		}
	})

	listeningPort := handler.getRestListeningPort()
	if cfg.EnableRESTTLS {
		m.RunTLS(fmt.Sprintf(":%d", listeningPort), cfg.RESTCert, cfg.RESTKey)
	} else {
		m.Run(fmt.Sprintf(":%d", listeningPort))
	}
}

func (handler *CoinstackHandle) getRestListeningPort() int {
	port := 3000
	if 0 < cfg.RESTListener {
		port = int(cfg.RESTListener)
	} else if envStr, exists := os.LookupEnv("PORT"); exists {
		envPort, err := strconv.Atoi(envStr)
		if nil == err {
			port = envPort
		} else {
			fmt.Printf("invalid value of env PORT: %s.\n", envStr)
			os.Exit(400)
		}
	}
	return port
}

func (handler *CoinstackHandle) DoGetBlockByHash(c *gin.Context) {
	format := c.Request.URL.Query().Get("format")
	block, ok, err := handler.db.FetchBlock(c.Param("blockhash"), format)
	if nil != err {
		coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
		c.JSON(coinstackErr.Status(), coinstackErr)
		return
	}
	if !ok {
		coinstackErr := client.NewCoinStackError(client.ResourceNotFound).SetCause("Requested block not found.")
		c.JSON(coinstackErr.Status(), coinstackErr)
		return
	}

	rw := c.Writer
	if b, ok := block.([]byte); ok {
		msg := hex.EncodeToString(b)
		rw.Header().Set("Content-Type", "text/plain")
		rw.WriteHeader(200)
		rw.Write([]byte(msg)) // nolint: errcheck
		return
	}
	cblock := block.(*client.Block)
	c.JSON(200, cblock)
}

func (handler *CoinstackHandle) DoGetBlockByHeight(c *gin.Context, height string) {
	blockHeight, err := strconv.Atoi(height)
	if err != nil {
		coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
		c.JSON(coinstackErr.Status(), coinstackErr)
		return
	}
	ids, err := handler.db.FetchBlockHeight(blockHeight)
	if err != nil {
		coinstackErr := client.NewCoinStackError(client.InternalServer).SetCause(err.Error())
		c.JSON(coinstackErr.Status(), coinstackErr)
		return
	}
	if len(ids) == 0 {
		coinstackErr := client.NewCoinStackError(client.ResourceNotFound).SetCause("Requested transaction not found.")
		c.JSON(coinstackErr.Status(), coinstackErr)
		return
	}
	c.JSON(200, ids)
}

type oaIndexFetcher interface {
	Meta(txHash *wire.ShaHash) []*openassets.Meta
	UnconfirmedMeta(txHash *wire.ShaHash) []*openassets.Meta
}

type oaFetcher struct {
	s *server
}

func (f *oaFetcher) Meta(txHash *wire.ShaHash) []*openassets.Meta {
	var meta []*openassets.Meta
	if err := f.s.db.View(func(dbTx database.Tx) error {
		meta = f.s.oaIndex.FetchMeta(dbTx, txHash)
		return nil
	}); err != nil {
		return nil
	}
	return meta
}

func (f *oaFetcher) UnconfirmedMeta(txHash *wire.ShaHash) []*openassets.Meta {
	return f.s.oaIndex.FetchUnconfirmedMeta(txHash)
}

type NoOpOaFetcher struct{}

func (*NoOpOaFetcher) Meta(txHash *wire.ShaHash) []*openassets.Meta {
	return nil
}

func (*NoOpOaFetcher) UnconfirmedMeta(txHash *wire.ShaHash) []*openassets.Meta {
	return nil
}

type CoinstackAdaptor struct {
	s            *server
	writeCounter uint64
	readCounter  uint64
	oaFetcher    oaIndexFetcher
}

func NewCoinstackAdaptor(server *server) (*CoinstackAdaptor, error) {
	adaptor := &CoinstackAdaptor{
		s:            server,
		writeCounter: 0,
		readCounter:  0,
	}
	if server.oaIndex != nil {
		adaptor.oaFetcher = &oaFetcher{s: server}
	} else {
		adaptor.oaFetcher = &NoOpOaFetcher{}
	}

	return adaptor, nil
}

func (adaptor *CoinstackAdaptor) SupportsTxBroadcast() bool {
	return true
}

func (adaptor *CoinstackAdaptor) PushTransaction(rawTx string) error {
	atomic.AddUint64(&adaptor.writeCounter, 1)

	hexStr := rawTx
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	serializedTx, err := hex.DecodeString(hexStr)
	if err != nil {
		return sync.IllegalTxError{Cause: err.Error()}
	}
	msgtx := wire.NewMsgTx()
	err = msgtx.Deserialize(bytes.NewReader(serializedTx))
	if err != nil {
		return sync.IllegalTxError{Cause: err.Error()}
	}

	tx := btcutil.NewTx(msgtx)
	acceptedTxs, err := adaptor.s.txMemPool.ProcessTransaction(tx, false, false)
	if err != nil {
		// When the error is a rule error, it means the transaction was
		// simply rejected as opposed to something actually going wrong,
		// so log it as such.  Otherwise, something really did go wrong,
		// so log it as an actual error.  In both cases, a JSON-RPC
		// error is returned to the client with the deserialization
		// error code (to match bitcoind behavior).
		if _, ok := err.(RuleError); ok {

			rpcsLog.Warnf("Rejected transaction %v: %v", tx.Sha(), err)

			return sync.IllegalTxError{Cause: err.Error()}
		}

		rpcsLog.Errorf("Failed to process transaction %v: %v",
			tx.Sha(), err)

		return err
	}

	rpcsLog.Debugf("Announce tranactions immediately: tx %v (%v accepted)",
		tx.Sha(), len(acceptedTxs))
	adaptor.s.AnnounceNewTransactionsImmediately(acceptedTxs)

	// Keep track of all the sendrawtransaction request txns so that they
	// can be rebroadcast if they don't make their way into a block.
	iv := wire.NewInvVect(wire.InvTypeTx, tx.Sha())
	adaptor.s.AddRebroadcastInventory(iv, tx)

	return nil
}

func (adaptor *CoinstackAdaptor) GetMempoolStatus() map[string]int {
	info := adaptor.s.txMemPool.GetMempoolStatus()
	return info
}

func (adaptor *CoinstackAdaptor) GetOrphanTxList() ([]string, error) {
	orprans := adaptor.s.txMemPool.GetOrphanTxList()
	return orprans, nil
}

func (adaptor *CoinstackAdaptor) GetMempoolTxList() ([]string, error) {
	orprans := adaptor.s.txMemPool.GetMempoolTxList()
	return orprans, nil
}

func (adaptor *CoinstackAdaptor) DumpAllMemTx() map[string]int {
	return adaptor.s.txMemPool.DumpAllMemTx()
}

func (adaptor *CoinstackAdaptor) GetBlockManagerDebugInfo() map[string][]string {
	return adaptor.s.blockManager.GetDebugInfo()
}

func (adaptor *CoinstackAdaptor) FetchTransaction(id string, format string) (interface{}, bool, error) {
	atomic.AddUint64(&adaptor.readCounter, 1)

	// Convert the provided transaction hash hex to a ShaHash.
	txHash, err := wire.NewShaHashFromStr(id)
	if err != nil {
		return nil, false, nil
	}

	// Try to fetch the transaction from the memory pool and if that fails,
	// try the block database.
	var mtx *wire.MsgTx
	var txBytes []byte
	var blockHeaderBytes []byte

	// load tx from mempool or database.
	// mempool have instance of MsgTx, but database returns raw txBytes.
	tx, err := adaptor.s.txMemPool.FetchTransaction(txHash)
	if err == nil {
		// tx found in mempool
		mtx = tx.MsgTx()
	} else {
		// tx not found in mempool
		// Load the raw transaction bytes from the database.
		err = adaptor.s.db.View(func(dbTx database.Tx) error {
			var e error
			blockHeaderBytes, txBytes, e = dbTx.FetchTransaction(txHash)
			return e
		})
		if err != nil || txBytes == nil {
			return nil, false, nil // tx not found
		}
	}

	if format == "hex" {
		// txBytes from database
		if txBytes != nil {
			return txBytes, true, nil
		}
		// mtx from mempool
		var buf bytes.Buffer
		mtx.Serialize(&buf) // nolint: errcheck
		return buf.Bytes(), true, nil
	}

	// txBytes from database
	if txBytes != nil && mtx == nil {
		// Deserialize the transaction
		var msgTx wire.MsgTx
		err = msgTx.Deserialize(bytes.NewReader(txBytes))
		if err != nil {
			return nil, false, errors.New(errDeserializeTx)
		}
		mtx = &msgTx
	}

	// The verbose flag is set, so generate the JSON object and return it.
	var blkHeader *wire.BlockHeader
	var blkHeight int32
	if blockHeaderBytes != nil {
		// Deserialize the header.
		var header wire.BlockHeader
		err = header.Deserialize(bytes.NewReader(blockHeaderBytes))
		if err != nil {
			return nil, false, errors.New(errDeserializeBlockHeader)
		}
		blkHeader = &header
		// Grab the block height.
		blkHash := blkHeader.BlockSha()
		blkHeight, err = adaptor.s.blockManager.chain.BlockHeightByHash(&blkHash)
		if err != nil {
			return nil, false, errors.New(errNotExistBlockHeight)
		}
	}

	view, err := adaptor.s.blockManager.chain.FetchUtxoView(btcutil.NewTx(mtx))
	if err != nil {
		return nil, false, errors.New("failed to fetch previous transaction")
	}

	var timestamp *time.Time
	if blkHeader != nil {
		timestamp = &blkHeader.Timestamp
	} else {
		now := time.Now()
		timestamp = &now
	}
	txResponse, err := adaptor.parseWireTx(mtx, sync.MAINNET, blkHeader, timestamp, blkHeight, view)

	if nil != err {
		return nil, false, err
	}

	return txResponse, true, nil
}

func (adaptor *CoinstackAdaptor) DeleteTransaction(id string) (bool, error) {
	atomic.AddUint64(&adaptor.writeCounter, 1)

	// Convert the provided transaction hash hex to a ShaHash.
	txHash, err := wire.NewShaHashFromStr(id)
	if err != nil {
		return false, err
	}

	// Try to fetch the transaction from the block database
	var mtx *wire.MsgTx

	// Unable to delete not confirmed transaction
	tx, err := adaptor.s.txMemPool.FetchTransaction(txHash)
	if err == nil && tx != nil {
		return true, fmt.Errorf("can not delete unconfirmed transaction")
	}

	// Load the raw transaction bytes from the database.
	var txBytes []byte
	err = adaptor.s.db.View(func(dbTx database.Tx) error {
		var e error
		_, txBytes, e = dbTx.FetchTransaction(txHash)
		return e
	})
	if err != nil || txBytes == nil {
		return false, nil // tx not found
	}

	// Deserialize the transaction
	var msgTx wire.MsgTx
	err = msgTx.Deserialize(bytes.NewReader(txBytes))
	if err != nil {
		return false, errors.New(errDeserializeTx)
	}
	mtx = &msgTx

	if !mtx.HasDeletableTxOut() {
		return false, fmt.Errorf("failed to find deletable tx output, OP_RETURN data script must be larger than %d bytes", wire.DeletedTxPayloadSize)
	}
	mtxHash := mtx.TxSha()
	if !txHash.IsEqual(&mtxHash) {
		return false, fmt.Errorf("failed to delete tx, invalid tx hash of %s, expected %s",
			txHash.String(), mtxHash.String())
	}

	err = adaptor.s.db.Update(func(dbTx database.Tx) error {
		success, err2 := indexers.DeleteTxFromDb(dbTx, mtx, indexers.DTOpTxID, nil)
		if err2 != nil {
			return err2
		}
		if !success {
			// not deletable: (err == nil && success == false)
			return fmt.Errorf("failed to delete transaction. not deletable")
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (adaptor *CoinstackAdaptor) FetchBlock(blockHash string, format string) (interface{}, bool, error) {
	atomic.AddUint64(&adaptor.readCounter, 1)

	// Load the raw block bytes from the database.
	hash, err := wire.NewShaHashFromStr(blockHash)
	if err != nil {
		return nil, false, nil // failure to decoding hash returns in not found
	}

	var blkBytes []byte
	err = adaptor.s.db.View(func(dbTx database.Tx) error {
		var e error
		blkBytes, e = dbTx.FetchBlock(hash)
		return e
	})
	if err != nil {
		return nil, false, nil // block not found
	}

	if format == "hex" {
		// blkBytes from database
		return blkBytes, true, nil
	}

	blk, err := btcutil.NewBlockFromBytes(blkBytes)
	if err != nil {
		return nil, false, errors.New(errDeserializeBlock)
	}

	// Get the block height from chain.
	blockHeight, err := adaptor.s.blockManager.chain.BlockHeightByHash(hash)
	if err != nil {
		return nil, false, errors.New(errNotExistBlockHeight)
	}
	best := adaptor.s.blockManager.chain.BestSnapshot()

	// Get next block hash unless there are none.
	var nextHashString string
	if blockHeight < best.Height {
		nextHash, err := adaptor.s.blockManager.chain.BlockHashByHeight(blockHeight + 1)
		if err != nil {
			return nil, false, errors.New(errNoNextBlock)
		}
		nextHashString = nextHash.String()
	}

	block := client.Block{
		Hash:   blockHash,
		Height: blockHeight,
		Time:   blk.MsgBlock().Header.Timestamp,
		Parent: blk.MsgBlock().Header.PrevBlock.String(),
	}

	if nextHashString != "" {
		block.Children = []string{nextHashString}
	}

	// fetch txs
	txns := blk.Transactions()
	block.Transactions = make([]string, len(txns))
	for i, tx := range txns {
		block.Transactions[i] = tx.Sha().String()
	}

	return &block, true, nil
}
func (adaptor *CoinstackAdaptor) FetchBlockHeight(blockHeight int) ([]string, error) {
	atomic.AddUint64(&adaptor.readCounter, 1)

	blkHash, err := adaptor.s.blockManager.chain.BlockHashByHeight(int32(blockHeight))
	if err != nil {
		return nil, errors.New("Failed to retrieve block by height")
	}
	ids := []string{blkHash.String()}
	return ids, nil
}

func (adaptor *CoinstackAdaptor) FetchBlockTransactions(blockHash string) ([]client.Transaction, error) {
	atomic.AddUint64(&adaptor.readCounter, 1)
	return []client.Transaction{}, nil
}

func (adaptor *CoinstackAdaptor) FetchBlockchainStatus() (*client.BlockchainStatus, error) {
	atomic.AddUint64(&adaptor.readCounter, 1)

	best := adaptor.s.blockManager.chain.BestSnapshot()
	return &client.BlockchainStatus{
		BestBlockHash: best.Hash.String(),
		BestHeight:    best.Height,
	}, nil
}

func (adaptor *CoinstackAdaptor) FetchTransactionHistory(address string) ([]string, error) {
	return adaptor.FetchTransactionHistoryPaged(address, 0, -1, -1)
}

func (adaptor *CoinstackAdaptor) FetchTransactionHistoryPaged(address string, skipCount int, numRequested int, confirmedFilter int) ([]string, error) {
	atomic.AddUint64(&adaptor.readCounter, 1)

	// Attempt to decode the supplied address.
	addr, err := btcutil.DecodeAddress(address, adaptor.s.chainParams)
	if err != nil {
		return nil, nil // not found
	}

	// If skip count is less than zero, it returns an error.
	if skipCount < 0 {
		return nil, errors.New("skip count must be greater than zero")
	}

	// Override the default number of requested entries if needed.  Also,
	// just return now if the number of requested entries is zero to avoid
	// extra work.
	batchSize := 128
	if numRequested > 0 && numRequested < batchSize {
		batchSize = numRequested
	}
	// Override the reverse flag if needed.
	reverse := true

	// Add transactions from mempool first if client asked for reverse
	// order.  Otherwise, they will be added last (as needed depending on
	// the requested counts).
	//
	// NOTE: This code doesn't sort by dependency.  This might be something
	// to do in the future for the client's convenience, or leave it to the
	// client.
	addressTxIDs := make([]wire.ShaHash, 0, batchSize)
	mempoolTxFetched := 0
	numSkipped := 0
	if confirmedFilter <= 0 {
		for {
			// Transactions in the mempool are not in a block header yet,
			// so the block header field in the retieved transaction struct
			// is left nil.
			fetchedBatch := 0
			mpTxns, mpSkipped := getMempoolTxnsForAddress(adaptor.s, addr,
				uint32(skipCount+mempoolTxFetched), uint32(batchSize))
			for _, tx := range mpTxns {
				addressTxIDs = append(addressTxIDs, *tx.Sha())
				mempoolTxFetched++
				fetchedBatch++
			}
			numSkipped += int(mpSkipped)

			if fetchedBatch < batchSize {
				break
			}

			if numRequested > -1 && len(addressTxIDs) >= numRequested {
				break
			}
		}
	}

	if confirmedFilter != 0 && (numRequested <= -1 || len(addressTxIDs) < numRequested) {
		// loop over until there is no more
		blockTxFetched := 0
		for {
			// Fetch transactions from the database in the desired order if more are
			// needed.
			fetchedBatch := 0
			err = adaptor.s.db.View(func(dbTx database.Tx) error {
				txIDs, _, e := adaptor.s.addrIndex.TxIDsForAddress(
					dbTx, addr, uint32(blockTxFetched)+uint32(skipCount)-uint32(numSkipped),
					uint32(batchSize), reverse)
				if e != nil {
					return e
				}

				for _, txID := range txIDs {
					addressTxIDs = append(addressTxIDs, txID)
					blockTxFetched++
					fetchedBatch++
				}
				return nil
			})

			if err != nil {
				context := "Failed to load address index entries"
				return nil, internalRPCError(err.Error(), context)
			}

			// no more items to fetch
			if fetchedBatch < batchSize {
				break
			}

			if numRequested > -1 && len(addressTxIDs) >= numRequested {
				break
			}
		}
	}

	// Address has never been used if neither source yielded any results.
	if len(addressTxIDs) == 0 {
		return []string{}, nil
	}

	// Serialize all of the transaction ids to string.
	// The results will be limited by the number requested.
	srtSize := len(addressTxIDs)
	if numRequested > -1 && srtSize > numRequested {
		srtSize = numRequested
	}
	srtList := make([]string, srtSize)
	for i := range addressTxIDs[0:srtSize] {

		rtxid := &addressTxIDs[i]

		srtList[i] = rtxid.String()
	}

	return srtList, nil
}
func (adaptor *CoinstackAdaptor) FetchBalance(address string) (int64, error) {
	atomic.AddUint64(&adaptor.readCounter, 1)

	var mempoolOutputs map[wire.OutPoint]*indexers.Output
	var blockOutputs map[wire.OutPoint]*indexers.Output

	adaptor.s.txMemPool.RLock()
	defer adaptor.s.txMemPool.RUnlock()

	err := adaptor.s.db.View(func(dbTx database.Tx) error {
		var err error
		mempoolOutputs, blockOutputs, err = adaptor.s.utxoIndex.FetchOutputs(dbTx, address)
		return err
	})

	if nil != err {
		return 0, internalRPCError(err.Error(), "failed to fetch utxos")
	}

	var balance int64
	best := adaptor.s.blockManager.chain.BestSnapshot()
	for _, output := range mempoolOutputs {
		var confirmations int32
		if output.Height > 0 {
			confirmations = 1 + best.Height - output.Height
		}

		_, exists := adaptor.s.txMemPool.outpoints[wire.OutPoint{Hash: *output.TxHash, Index: output.Vout}]
		if exists {
			continue
		}

		if !output.Coinbase || confirmations >= blockchain.CoinbaseMaturity {
			balance = balance + output.Amount
		}
	}
	for _, output := range blockOutputs {
		var confirmations int32
		if output.Height > 0 {
			confirmations = 1 + best.Height - output.Height
		}

		// prevent concurrent mempool outpoint read/write
		//adaptor.s.txMemPool.RLock()
		_, exists := adaptor.s.txMemPool.outpoints[wire.OutPoint{Hash: *output.TxHash, Index: output.Vout}]
		//adaptor.s.txMemPool.RUnlock()
		if exists {
			continue
		}

		if !output.Coinbase || confirmations >= blockchain.CoinbaseMaturity {
			balance = balance + output.Amount
		}
	}

	return balance, nil
}

func (adaptor *CoinstackAdaptor) SupportsWebsocket() bool {
	return true
}

func (adaptor *CoinstackAdaptor) AddBlockHandler(blockEvent *client.BlockEvent) {
	adaptor.s.rpcServer.ntfnMgr.AddBlockEvent(interface{}(blockEvent), (BlockEvent)(func(block *btcutil.Block) {
		// Get the block height from chain.
		blockHeight, err := adaptor.s.blockManager.chain.BlockHeightByHash(block.Sha())
		if err != nil {
			blockHeight = -1
		}
		(*blockEvent)(&client.Block{
			Hash:   block.Sha().String(),
			Height: blockHeight,
			Time:   block.MsgBlock().Header.Timestamp,
			Parent: block.MsgBlock().Header.PrevBlock.String(),
		})
	}))
}
func (adaptor *CoinstackAdaptor) RemoveBlockHandler(blockEvent *client.BlockEvent) {
	adaptor.s.rpcServer.ntfnMgr.RemoveBlockEvent(interface{}(blockEvent))
}
func (adaptor *CoinstackAdaptor) AddTxHandler(txEvent *client.TxEvent) {
	adaptor.s.rpcServer.ntfnMgr.AddTxEvent(interface{}(txEvent), (TxEvent)(func(tx *btcutil.Tx) {
		timestamp := time.Now()
		(*txEvent)(&client.Transaction{
			Hash:          tx.Sha().String(),
			BroadcastTime: &timestamp,
			Time:          &timestamp,
		})
	}))
}
func (adaptor *CoinstackAdaptor) RemoveTxHandler(txEvent *client.TxEvent) {
	adaptor.s.rpcServer.ntfnMgr.RemoveTxEvent(interface{}(txEvent))
}

func (adaptor *CoinstackAdaptor) FetchUnspentOutputs(address string, reqAmount int64) ([]client.UnspentOutput, error) {
	atomic.AddUint64(&adaptor.readCounter, 1)

	var mempoolOutputs map[wire.OutPoint]*indexers.Output
	var blockOutputs map[wire.OutPoint]*indexers.Output

	adaptor.s.txMemPool.RLock()
	defer adaptor.s.txMemPool.RUnlock()

	err := adaptor.s.db.View(func(dbTx database.Tx) error {
		var err error
		mempoolOutputs, blockOutputs, err = adaptor.s.utxoIndex.FetchOutputs(dbTx, address)
		return err
	})

	if nil != err {
		return nil, internalRPCError(err.Error(), "failed to fetch utxos")
	}

	var sumAmount int64 = 0
	utxoResult := make([]client.UnspentOutput, len(mempoolOutputs)+len(blockOutputs))
	utxoIndex := 0
	best := adaptor.s.blockManager.chain.BestSnapshot()
	for _, output := range mempoolOutputs {
		var confirmations int32
		if output.Height > 0 {
			confirmations = 1 + best.Height - output.Height
		}

		// prevent concurrent mempool outpoint read/write
		//adaptor.s.txMemPool.RLock()
		_, exists := adaptor.s.txMemPool.outpoints[wire.OutPoint{Hash: *output.TxHash, Index: output.Vout}]
		//adaptor.s.txMemPool.RUnlock()
		if exists {
			continue
		}

		if !output.Coinbase || confirmations >= blockchain.CoinbaseMaturity {
			utxoResult[utxoIndex] = client.UnspentOutput{
				TransactionHash: reverseEndianness(output.TxHash.String()),
				Index:           int32(output.Vout),
				Value:           fmt.Sprintf("%v", output.Amount),
				Confirmations:   confirmations,
				Script:          hex.EncodeToString(output.Script),
			}
			// populate openassets metadata
			outputMeta := adaptor.oaFetcher.UnconfirmedMeta(output.TxHash)
			if len(outputMeta) > 0 {
				utxoResult[utxoIndex].Metadata = makeClientAssetMeta(outputMeta[output.Vout])
			}
			utxoIndex++
			if reqAmount > 0 {
				if sumAmount += output.Amount; reqAmount <= sumAmount {
					return utxoResult[:utxoIndex], nil
				}
			}
		}
	}

	for _, output := range blockOutputs {
		var confirmations int32
		if output.Height > 0 {
			confirmations = 1 + best.Height - output.Height
		}

		// prevent concurrent mempool outpoint read/write
		//adaptor.s.txMemPool.RLock()
		_, exists := adaptor.s.txMemPool.outpoints[wire.OutPoint{Hash: *output.TxHash, Index: output.Vout}]
		//adaptor.s.txMemPool.RUnlock()
		if exists {
			continue
		}

		if !output.Coinbase || confirmations >= blockchain.CoinbaseMaturity {
			utxoResult[utxoIndex] = client.UnspentOutput{
				TransactionHash: reverseEndianness(output.TxHash.String()),
				Index:           int32(output.Vout),
				Value:           fmt.Sprintf("%v", output.Amount),
				Confirmations:   confirmations,
				Script:          hex.EncodeToString(output.Script),
			}
			// populate openassets metadata
			outputMeta := adaptor.oaFetcher.Meta(output.TxHash)
			if len(outputMeta) > 0 {
				utxoResult[utxoIndex].Metadata = makeClientAssetMeta(outputMeta[output.Vout])
			}
			utxoIndex++
			if reqAmount > 0 {
				if sumAmount += output.Amount; reqAmount <= sumAmount {
					return utxoResult[:utxoIndex], nil
				}
			}
		}
	}

	return utxoResult[:utxoIndex], nil
}

func makeClientAssetMeta(meta *openassets.Meta) *client.Metadata {
	openAssetMeta := &client.Metadata{
		OpenAssets: &client.OpenAssetsMeta{
			Version: &client.OpenAssetsVersion{
				MajorVersion: meta.MajorVersion,
				MinorVersion: meta.MinorVersion,
			},
			Quantity: meta.Quantity,
		},
	}
	info := openassets.MetaInfos[meta.OutputType]
	openAssetMeta.OpenAssets.OutputType = info.Name
	if info.UseAssetID {
		openAssetMeta.OpenAssets.AssetID = openassets.CalculateBase58(meta.AssetID)
	}
	return openAssetMeta
}

var coinbaseHash = &wire.ShaHash{}

func (adaptor *CoinstackAdaptor) parseWireTx(
	btcdwireTx *wire.MsgTx,
	networkType sync.NetworkType,
	blockHeader *wire.BlockHeader,
	timestamp *time.Time,
	height int32,
	view *blockchain.UtxoViewpoint,
) (*client.Transaction, error) {
	inputs := make([]client.Input, len(btcdwireTx.TxIn))
	outputs := make([]client.Output, len(btcdwireTx.TxOut))
	isCoinbase := false
	txAddresses := []string{}
	var chainParams *chaincfg.Params
	switch networkType {
	case sync.MAINNET:
		chainParams = &chaincfg.MainNetParams
	case sync.TESTNET:
		chainParams = &chaincfg.TestNet3Params
	case sync.REGTESTNET:
		chainParams = &chaincfg.RegressionNetParams
	case sync.PRIVNET:
		chainParams = &chaincfg.PrivateNetParams
	}

	// fetch previous outputs
	var originOutputs map[wire.OutPoint]wire.TxOut
	var err error

	for i, input := range btcdwireTx.TxIn {
		if input.PreviousOutPoint.Hash.IsEqual(coinbaseHash) {
			inputs[i] = client.Input{}
			isCoinbase = true
			inputs = []client.Input{}
			continue
		} else {
			if originOutputs == nil {
				originOutputs, err = fetchPreviousTxos(adaptor.s, btcdwireTx)
				if nil != err {
					return nil, err
				}
			}
			previousOutput := originOutputs[input.PreviousOutPoint]
			inputs[i] = client.Input{
				TransactionHash: input.PreviousOutPoint.Hash.String(),
				OutputIndex:     int32(input.PreviousOutPoint.Index),
				Value:           fmt.Sprintf("%v", previousOutput.Value),
			}
			pkScript := previousOutput.PkScript
			_, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript,
				chainParams)
			if nil != err || len(addrs) < 1 {
				continue
			}
			inputs[i].Address = []string{addrs[0].EncodeAddress()}
		}

	}

	for i, output := range btcdwireTx.TxOut {
		// extract address
		outputs[i] = client.Output{
			Index:  int32(i),
			Value:  strconv.FormatInt(output.Value, 10),
			Script: hex.EncodeToString(output.PkScript),
			Spent:  false,
		}

		// extract address from script
		_, btcdwireAddresses, _, err :=
			txscript.ExtractPkScriptAddrs(output.PkScript, chainParams)
		addresses := make([]string, len(btcdwireAddresses))
		if nil != err {
			continue
		}
		for i, address := range btcdwireAddresses {
			addresses[i] = address.EncodeAddress()
		}
		outputs[i].Address = addresses
		txAddresses = append(txAddresses, addresses...)
	}

	isDeleted := btcdwireTx.IsDeleted()

	txHash := btcdwireTx.TxSha()
	tx := client.Transaction{
		Hash:      txHash.String(),
		Coinbase:  isCoinbase,
		Inputs:    inputs,
		Outputs:   outputs,
		IsDeleted: isDeleted,
		Addresses: txAddresses,
		Time:      timestamp,
	}

	// try to fetch openassets meta
	var outputMeta []*openassets.Meta
	if blockHeader != nil {
		outputMeta = adaptor.oaFetcher.Meta(&txHash)
	} else {
		outputMeta = adaptor.oaFetcher.UnconfirmedMeta(&txHash)
	}
	for i, meta := range outputMeta {
		tx.Outputs[i].Metadata = makeClientAssetMeta(meta)
	}

	if blockHeader != nil {
		tx.Blocks = []client.BlockHash{{Hash: blockHeader.BlockSha().String(), Height: height}}
	} else {
		tx.Blocks = []client.BlockHash{}
	}
	return &tx, nil
}

// fetchMempoolTxnsForAddress queries the address index for all unconfirmed
// transactions that involve the provided address.  The results will be limited
// by the number to skip and the number requested.
func getMempoolTxnsForAddress(s *server, addr btcutil.Address, numToSkip, numRequested uint32) ([]*btcutil.Tx, uint32) {
	// There are no entries to return when there are less available than the
	// number being skipped.
	mpTxns := s.addrIndex.UnconfirmedTxnsForAddress(addr)
	numAvailable := uint32(len(mpTxns))
	if numToSkip == numAvailable {
		return nil, 0
	}
	if numToSkip > numAvailable {
		return nil, numAvailable
	}

	// Filter the available entries based on the number to skip and number
	// requested.
	rangeEnd := numToSkip + numRequested
	if rangeEnd > numAvailable {
		rangeEnd = numAvailable
	}
	return mpTxns[numToSkip:rangeEnd], numToSkip
}

// fetchInputTxos fetches the outpoints from all transactions referenced by the
// inputs to the passed transaction by checking the transaction mempool first
// then the transaction index for those already mined into blocks.
func fetchPreviousTxos(s *server, tx *wire.MsgTx) (map[wire.OutPoint]wire.TxOut, error) {
	mp := s.txMemPool
	originOutputs := make(map[wire.OutPoint]wire.TxOut)
	for txInIndex, txIn := range tx.TxIn {
		// Attempt to fetch and use the referenced transaction from the
		// memory pool.
		origin := &txIn.PreviousOutPoint
		originTx, err := mp.FetchTransaction(&origin.Hash)
		if err == nil {
			txOuts := originTx.MsgTx().TxOut
			if origin.Index >= uint32(len(txOuts)) {
				errStr := fmt.Sprintf("unable to find output "+
					"%v referenced from transaction %s:%d",
					origin, tx.TxSha(), txInIndex)
				return nil, internalRPCError(errStr, "")
			}

			originOutputs[*origin] = *txOuts[origin.Index]
			continue
		}

		// Load the raw transaction bytes from the database.
		var txBytes []byte
		err = s.db.View(func(dbTx database.Tx) error {
			var e error
			_, txBytes, e = dbTx.FetchTransaction(&origin.Hash)
			return e
		})
		if err != nil || txBytes == nil {
			return nil, rpcNoTxInfoError(&origin.Hash)
		}

		// Deserialize the transaction
		var msgTx wire.MsgTx
		err = msgTx.Deserialize(bytes.NewReader(txBytes))
		if err != nil {
			return nil, internalRPCError(err.Error(), errDeserializeTx)
		}

		// Add the referenced output to the map.
		if origin.Index >= uint32(len(msgTx.TxOut)) {
			errStr := fmt.Sprintf("unable to find output %v "+
				"referenced from transaction %s:%d", origin,
				tx.TxSha(), txInIndex)
			return nil, internalRPCError(errStr, "")
		}
		originOutputs[*origin] = *msgTx.TxOut[origin.Index]
	}

	return originOutputs, nil
}

func reverseEndianness(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+2, j-2 {
		runes[i], runes[j-1] = runes[j-1], runes[i]
		runes[i+1], runes[j] = runes[j], runes[i+1]
	}
	return string(runes)
}

func (adaptor *CoinstackAdaptor) SupportsSmartContract() bool {
	return true
}

func (adaptor *CoinstackAdaptor) SupportsPermission() bool {
	if adaptor.s.permIndex != nil {
		return true
	}
	return false
}

func (adaptor *CoinstackAdaptor) FetchContractStatus(address string) (*client.ContractStatus, bool, error) {
	initialized := false
	contractType := ""
	contractHash := ""

	if adaptor.s.ismIndex == nil {
		return nil, false, errors.New("smart contract is not enabled")
	}

	if adaptor.s.ismIndex.EphemeralEnabled {
		adaptor.s.ismIndex.EphemeralLock.RLock()
		defer adaptor.s.ismIndex.EphemeralLock.RUnlock()
	}

	err := adaptor.s.db.View(func(dbTx database.Tx) error {
		initialized, contractType, contractHash = adaptor.s.ismIndex.FetchContractStatus(dbTx, address)
		return nil
	})
	if nil != err {
		return nil, false, err
	}

	if !initialized {
		return nil, false, nil
	}

	return &client.ContractStatus{
		ContractID:   []string{address},
		Terminated:   false,
		ContractHash: contractHash,
		ContractType: contractType,
	}, initialized, nil
}

func (adaptor *CoinstackAdaptor) QueryContract(address string, query *json.RawMessage) (*indexers.ISMQueryResult, bool, error) {
	if adaptor.s.ismIndex == nil {
		return nil, false, errors.New("smart contract is not enabled")
	}

	atomic.AddUint64(&adaptor.readCounter, 1)

	if adaptor.s.ismIndex.EphemeralEnabled {
		adaptor.s.ismIndex.EphemeralLock.RLock()
		defer adaptor.s.ismIndex.EphemeralLock.RUnlock()
	}

	var result *indexers.ISMQueryResult

	if err := adaptor.s.db.View(func(dbTx database.Tx) error {
		var e error
		result, e = adaptor.s.ismIndex.QueryContract(dbTx, address, query)
		return e
	}); err != nil {
		return nil, false, err
	}

	return result, true, nil
}

func (adaptor *CoinstackAdaptor) FetchContractGrantees(address string) []*client.ContractGrantee {
	if adaptor.s.ismIndex == nil {
		return []*client.ContractGrantee{}
	}

	atomic.AddUint64(&adaptor.readCounter, 1)

	if adaptor.s.ismIndex.EphemeralEnabled {
		adaptor.s.ismIndex.EphemeralLock.RLock()
		defer adaptor.s.ismIndex.EphemeralLock.RUnlock()
	}

	var grantees []*client.ContractGrantee

	if err := adaptor.s.db.View(func(dbTx database.Tx) error {
		grantees = adaptor.s.ismIndex.FetchContractGrantees(dbTx, address)
		return nil
	}); err != nil {
		return []*client.ContractGrantee{}
	}

	return grantees
}

func (adaptor *CoinstackAdaptor) FetchContractStats() *client.ContractStat {
	if adaptor.s.ismIndex == nil {
		return nil
	}

	if adaptor.s.ismIndex.EphemeralEnabled {
		adaptor.s.ismIndex.EphemeralLock.RLock()
		defer adaptor.s.ismIndex.EphemeralLock.RUnlock()
	}

	var stat *client.ContractStat

	if err := adaptor.s.db.View(func(dbTx database.Tx) error {
		stat = adaptor.s.ismIndex.FetchContractStats()
		return nil
	}); err != nil {
		return &client.ContractStat{}
	}

	return stat
}

func (adaptor *CoinstackAdaptor) GetBytes(key string) ([]byte, bool, error) {
	atomic.AddUint64(&adaptor.readCounter, 1)

	switch key {
	case "NodeGroupPubKeyBytes":
		return adaptor.s.ismIndex.GetNodeGroupPubKeyBytes(), true, nil
	default:
		return nil, false, errors.New("cannot recognize key")
	}
}

// FetchEnabledPermissions returns a enabled permission roles in byte
func (adaptor *CoinstackAdaptor) FetchEnabledPermissions() *client.Permission {
	atomic.AddUint64(&adaptor.readCounter, 1)

	var permission byte
	if err := adaptor.s.db.View(func(dbTx database.Tx) error {
		permission = adaptor.s.permIndex.GetEnabledPermission(dbTx)
		return nil
	}); err != nil {
		return &client.Permission{}
	}

	return &client.Permission{
		Permission: permission,
	}
}

func (adaptor *CoinstackAdaptor) FetchPermission(address string) *client.Permission {
	atomic.AddUint64(&adaptor.readCounter, 1)

	var permission byte
	if err := adaptor.s.db.View(func(dbTx database.Tx) error {
		permission = adaptor.s.permIndex.GetPermission(dbTx, address)
		return nil
	}); err != nil {
		return &client.Permission{}
	}

	return &client.Permission{
		Permission: permission,
	}
}

func (adaptor *CoinstackAdaptor) FetchAllPermissions() (map[string]byte, error) {
	atomic.AddUint64(&adaptor.readCounter, 1)

	var addrPermissionMap map[string]byte
	err := adaptor.s.db.View(func(dbTx database.Tx) error {
		var innerErr error
		addrPermissionMap, innerErr = adaptor.s.permIndex.ListAllPermission(dbTx)
		return innerErr
	})

	return addrPermissionMap, err
}

func (adaptor *CoinstackAdaptor) FetchPublickey(alias string) *client.Publickey {
	atomic.AddUint64(&adaptor.readCounter, 1)

	var publickey []byte
	if err := adaptor.s.db.View(func(dbTx database.Tx) error {
		if adaptor.s.permIndex != nil {
			publickey = adaptor.s.permIndex.GetAliasPublickey(dbTx, alias)
		}
		return nil
	}); err != nil {
		return &client.Publickey{}
	}

	return &client.Publickey{
		Publickey: publickey,
	}
}

func (adaptor *CoinstackAdaptor) FetchAllPublickeys() (map[string][]byte, error) {
	atomic.AddUint64(&adaptor.readCounter, 1)

	var aliasPublickeyMap map[string][]byte
	err := adaptor.s.db.View(func(dbTx database.Tx) error {
		var innerErr error
		aliasPublickeyMap, innerErr = adaptor.s.permIndex.ListAlias(dbTx)
		return innerErr
	})

	return aliasPublickeyMap, err
}

func (adaptor *CoinstackAdaptor) EnableDebug() bool {
	return adaptor.s.enableDebug
}

func (adaptor *CoinstackAdaptor) FetchWriteCounter() uint64 {
	return atomic.LoadUint64(&adaptor.writeCounter)
}

func (adaptor *CoinstackAdaptor) FetchReadCounter() uint64 {
	return atomic.LoadUint64(&adaptor.readCounter)
}

func (adaptor *CoinstackAdaptor) EnableKVStore() bool {
	return adaptor.s.enableKVStore
}

func (adaptor *CoinstackAdaptor) FetchContractSource(address string) (string, error) {
	atomic.AddUint64(&adaptor.readCounter, 1)

	if adaptor.s.ismIndex == nil {
		return "", errors.New("smart contract is not enabled")
	}

	if adaptor.s.ismIndex.EphemeralEnabled {
		adaptor.s.ismIndex.EphemeralLock.RLock()
		defer adaptor.s.ismIndex.EphemeralLock.RUnlock()
	}

	var source string
	err := adaptor.s.db.View(func(dbTx database.Tx) error {
		var e error
		source, e = adaptor.s.ismIndex.FetchContractSource(dbTx, address)
		return e
	})
	return source, err
}

func (adaptor *CoinstackAdaptor) FetchContractFnSigs(address string) ([]*client.ContractFnSig, error) {
	atomic.AddUint64(&adaptor.readCounter, 1)

	if adaptor.s.ismIndex == nil {
		return nil, errors.New("smart contract is not enabled")
	}

	if adaptor.s.ismIndex.EphemeralEnabled {
		adaptor.s.ismIndex.EphemeralLock.RLock()
		defer adaptor.s.ismIndex.EphemeralLock.RUnlock()
	}

	var fns []*client.ContractFnSig
	err := adaptor.s.db.View(func(dbTx database.Tx) error {
		var e error
		fns, e = adaptor.s.ismIndex.FetchContractFnSigs(dbTx, address)
		return e
	})
	return fns, err
}
