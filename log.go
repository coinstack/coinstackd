// Copyright (c) 2016 BLOCKO INC.
// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/coinstack/coinstackd/addrmgr"
	"github.com/coinstack/coinstackd/blockchain"
	"github.com/coinstack/coinstackd/blockchain/indexers"
	"github.com/coinstack/coinstackd/blockchain/indexers/ism"
	"github.com/coinstack/coinstackd/blockchain/indexers/ism/sql"
	"github.com/coinstack/coinstackd/blockchain/indexers/openassets"
	"github.com/coinstack/coinstackd/blockchain/indexers/opencontracts"
	"github.com/coinstack/coinstackd/coinstack/crypto"
	"github.com/coinstack/coinstackd/database"
	"github.com/coinstack/coinstackd/event"
	"github.com/coinstack/coinstackd/peer"
	"github.com/coinstack/coinstackd/txscript"
	"github.com/btcsuite/btclog"
	"github.com/btcsuite/seelog"
)

// Loggers per subsystem.  Note that backendLog is a seelog logger that all of
// the subsystem loggers route their messages to.  When adding new subsystems,
// add a reference here, to the subsystemLoggers map, and the useLogger
// function.
var (
	backendLog = seelog.Disabled
	admLog     = seelog.Disabled
	adxrLog    = btclog.Disabled
	amgrLog    = btclog.Disabled
	bcdbLog    = btclog.Disabled
	bmgrLog    = btclog.Disabled
	btcdLog    = btclog.Disabled
	chanLog    = btclog.Disabled
	discLog    = btclog.Disabled
	indxLog    = btclog.Disabled
	minrLog    = btclog.Disabled
	peerLog    = btclog.Disabled
	rpcsLog    = btclog.Disabled
	scrpLog    = btclog.Disabled
	srvrLog    = btclog.Disabled
	txmpLog    = btclog.Disabled
	evntLog    = btclog.Disabled
	restLog    = btclog.Disabled
	ismLog     = btclog.Disabled
)

// subsystemLoggers maps each subsystem identifier to its associated logger.
var subsystemLoggers = map[string]btclog.Logger{
	"ADXR": adxrLog,
	"AMGR": amgrLog,
	"BCDB": bcdbLog,
	"BMGR": bmgrLog,
	"BTCD": btcdLog,
	"CHAN": chanLog,
	"DISC": discLog,
	"INDX": indxLog,
	"MINR": minrLog,
	"PEER": peerLog,
	"RPCS": rpcsLog,
	"SCRP": scrpLog,
	"SRVR": srvrLog,
	"TXMP": txmpLog,
	"EVNT": evntLog,
	"REST": restLog,
	"SMCT": ismLog,
}

// useLogger updates the logger references for subsystemID to logger.  Invalid
// subsystems are ignored.
func useLogger(subsystemID string, logger btclog.Logger) {
	if _, ok := subsystemLoggers[subsystemID]; !ok {
		return
	}
	subsystemLoggers[subsystemID] = logger

	switch subsystemID {
	case "ADXR":
		adxrLog = logger

	case "AMGR":
		amgrLog = logger
		addrmgr.UseLogger(logger)

	case "BCDB":
		bcdbLog = logger
		database.UseLogger(logger)

	case "BMGR":
		bmgrLog = logger

	case "BTCD":
		btcdLog = logger

	case "CHAN":
		chanLog = logger
		blockchain.UseLogger(logger)

	case "DISC":
		discLog = logger

	case "INDX":
		indxLog = logger
		indexers.UseLogger(logger)
		openassets.UseLogger(logger)
		opencontracts.UseLogger(logger)
		crypto.UseLogger(logger)

	case "MINR":
		minrLog = logger

	case "PEER":
		peerLog = logger
		peer.UseLogger(logger)

	case "RPCS":
		rpcsLog = logger

	case "SCRP":
		scrpLog = logger
		txscript.UseLogger(logger)

	case "SRVR":
		srvrLog = logger

	case "TXMP":
		txmpLog = logger

	case "EVNT":
		evntLog = logger
		event.UseLogger(logger)

	case "REST":
		restLog = logger

	case "SMCT":
		ismLog = logger
		ism.UseLogger(logger)
		sql.UseLogger(logger)
	}
}

func newLoggerOrExit(config string) seelog.LoggerInterface {
	logger, err := seelog.LoggerFromConfigAsString(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create logger: %v", err)
		os.Exit(1)
	}

	return logger
}

const (
	// LogRollingTypeDate -- sate-based rolling
	LogRollingTypeDate = iota
	// LogRollingTypeSize -- size-based rolling
	LogRollingTypeSize = iota
	// LogRollingTypeMax -- max # of rolling type
	LogRollingTypeMax = iota

	admLogFilename = "critical.log"
)

func rollingFile(cfg config, admLog bool) string {
	rollFmt := [LogRollingTypeMax]string{
		LogRollingTypeDate: `<rollingfile type="date" datepattern="02.01.2006" filename="%s" maxrolls="%d" />`,
		LogRollingTypeSize: `<rollingfile type="size" filename="%s" maxrolls="%d" maxsize="` + fmt.Sprintf("%d", cfg.LogMaxSize) + `" />`,
	}

	rollMax := [LogRollingTypeMax]int{
		LogRollingTypeDate: cfg.LogMaxDays,
		LogRollingTypeSize: cfg.LogMaxRolls,
	}

	var name string
	if admLog {
		name = filepath.Join(cfg.LogDir, admLogFilename)
	} else {
		name = filepath.Join(cfg.LogDir, defaultLogFilename)
	}

	return fmt.Sprintf(rollFmt[cfg.LogRollingType], name, rollMax[cfg.LogRollingType])
}

func getConfigHeader(admLog bool) string {
	const (
		format = `<seelog type="%s" mininterval="2000000" maxinterval="100000000"
                    critmsgcount="500" minlevel="trace">
                    <outputs formatid="all">
                        <console />
               `
	)

	var typ string
	if admLog {
		typ = "sync"
	} else {
		typ = "adaptive"
	}

	return fmt.Sprintf(format, typ)
}

// makeLogFileConfig generates an XML config string from config. There are 4
// different configurations: size-based or date-based with or without critical
// log.
func makeLogConfig(cfg config, admLog bool) string {
	const footer = `
                    </outputs> 
                    <formats>
                        <format id="all" format="%Time %Date [%LEV] %Msg%n" />
                    </formats>
                </seelog>`

	buffer := bytes.NewBufferString(getConfigHeader(admLog))
	buffer.WriteString(rollingFile(cfg, admLog))
	buffer.WriteString(footer)

	return buffer.String()
}

// AdmLogger provides a seperate logging (admin log), to which only the log
// messages of error & critical level are written.
type AdmLogger struct {
	btclog.Logger
	admLog seelog.LoggerInterface
}

// Errorf wrapper for admin log.
func (aLog *AdmLogger) Errorf(format string, params ...interface{}) error {
	aLog.admLog.Errorf(format, params...)

	return aLog.Logger.Errorf(format, params...)
}

// Error wrapper for admin log.
func (aLog *AdmLogger) Error(v ...interface{}) error {
	aLog.admLog.Error(v...)

	return aLog.Logger.Error(v...)
}

// Criticalf wrapper for admin log.
func (aLog *AdmLogger) Criticalf(format string, params ...interface{}) error {
	aLog.admLog.Criticalf(format, params...)

	return aLog.Logger.Criticalf(format, params...)
}

// Critical wrapper for admin log.
func (aLog *AdmLogger) Critical(v ...interface{}) error {
	aLog.admLog.Critical(v...)

	return aLog.Logger.Critical(v...)
}

func (aLog *AdmLogger) admInfof(format string, params ...interface{}) {
	aLog.admLog.Infof(format, params...)
	aLog.Logger.Infof(format, params...)
}

func (aLog *AdmLogger) admInfo(v ...interface{}) {
	aLog.admLog.Info(v...)
	aLog.Logger.Info(v...)
}

func (aLog *AdmLogger) admWarnf(format string, params ...interface{}) {
	aLog.admLog.Warnf(format, params...)
	aLog.Logger.Warnf(format, params...)
}

func (aLog *AdmLogger) admWarn(v ...interface{}) {
	aLog.admLog.Warn(v...)
	aLog.Logger.Warn(v...)
}

// AdmInfof writes Info level log both to default and admin log. It can be used
// to write info level log messages both to the critical and default log file.
func AdmInfof(logger btclog.Logger, format string, params ...interface{}) {
	if admLog, ok := logger.(*AdmLogger); ok {
		admLog.admInfof(format, params...)
	} else {
		logger.Infof(format, params...)
	}
}

// AdmInfo writes Info level log both to default and admin log. It can be used
// to write info level log messages both to the critical and default log file.
func AdmInfo(logger btclog.Logger, v ...interface{}) {
	if admLog, ok := logger.(*AdmLogger); ok {
		admLog.admInfo(v...)
	} else {
		logger.Info(v...)
	}
}

// AdmWarn writes Warn level log both to default and admin log. It can be used
// to write info level log messages both to the critical and default log file.
func AdmWarn(logger btclog.Logger, v ...interface{}) {
	if admLog, ok := logger.(*AdmLogger); ok {
		admLog.admWarn(v...)
	} else {
		logger.Warn(v...)
	}
}

// initSeelogLogger initializes a new seelog logger that is used as the backend
// for all logging subsystems.
func initSeelogLogger(cfg config) {
	backendLog = newLoggerOrExit(makeLogConfig(cfg, false))

	if cfg.CriticalLog {
		admLog = newLoggerOrExit(makeLogConfig(cfg, true))
	}
}

// setLogLevel sets the logging level for provided subsystem.  Invalid
// subsystems are ignored.  Uninitialized subsystems are dynamically created as
// needed.
func setLogLevel(subsystemID string, logLevel string) {
	// Ignore invalid subsystems.
	logger, ok := subsystemLoggers[subsystemID]
	if !ok {
		return
	}

	// Default to info if the log level is invalid.
	level, ok := btclog.LogLevelFromString(logLevel)
	if !ok {
		level = btclog.InfoLvl
	}

	// Create new logger for the subsystem if needed.
	if logger == btclog.Disabled {
		logger = btclog.NewSubsystemLogger(backendLog, subsystemID+": ")

		if admLog != seelog.Disabled {
			logger = &AdmLogger{
				Logger: logger,
				admLog: admLog,
			}
		}

		useLogger(subsystemID, logger)
	}
	logger.SetLevel(level)
}

// setLogLevels sets the log level for all subsystem loggers to the passed
// level.  It also dynamically creates the subsystem loggers as needed, so it
// can be used to initialize the logging system.
func setLogLevels(logLevel string) {
	// Configure all sub-systems with the new logging level.  Dynamically
	// create loggers as needed.
	for subsystemID := range subsystemLoggers {
		setLogLevel(subsystemID, logLevel)
	}
}

// directionString is a helper function that returns a string that represents
// the direction of a connection (inbound or outbound).
func directionString(inbound bool) string {
	if inbound {
		return "inbound"
	}
	return "outbound"
}
