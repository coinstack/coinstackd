// Copyright (c) 2016 BLOCKO INC.
// Package client comes from github.com/coinstack/coinstack-client
// And this errors.go file comes from errors.go of coinstack-client
package client

import (
	"bytes"
	"strconv"
)

// CoinStackError is base error type for coinstack
type CoinStackError struct {
	ErrorType  string `json:"error_type"`
	ErrorCode  int    `json:"error_code"`
	StatusCode int    `json:"-"`
	Message    string `json:"error_message"`
	Retry      bool   `json:"retry"`
	Cause      string `json:"error_cause,omitempty"`
}

func (error *CoinStackError) Error() string {
	return error.Message
}

func (error *CoinStackError) Status() int {
	return error.StatusCode
}

func (error *CoinStackError) String() string {
	if error == nil {
		return ""
	}
	var buffer bytes.Buffer
	buffer.WriteString("error_code:")
	buffer.WriteString(strconv.Itoa(error.ErrorCode))
	buffer.WriteString("\nerror_message:")
	buffer.WriteString(error.Message)
	buffer.WriteString("\nerror_cause:")
	buffer.WriteString(error.Cause)
	return buffer.String()
}

// client error codes
const (
	_ = iota + 3000
	AccessDenied
	ThroughputExceeded
	ResourceNotFound
	ValidationFailed
)

// server error codes
const (
	_ = iota + 4000
	InternalServer
	ServerUnavailable
)

// error definitions
var coinstackErrors = map[int]CoinStackError{
	// client errors
	AccessDenied: {
		ErrorType:  "io.coinstack#AccessDeniedError",
		ErrorCode:  AccessDenied,
		StatusCode: 400,
		Message:    "Access Denied",
		Retry:      false,
	},
	ThroughputExceeded: {
		ErrorType:  "io.coinstack#ThroughputExceededError",
		ErrorCode:  ThroughputExceeded,
		StatusCode: 400,
		Message:    "Rate of requests exceeds the allowed throughput.",
		Retry:      true,
	},
	ResourceNotFound: {
		ErrorType:  "io.coinstack#ResourceNotFoundError",
		ErrorCode:  ResourceNotFound,
		StatusCode: 404,
		Message:    "Requested resource not found.",
		Retry:      false,
	},
	ValidationFailed: {
		ErrorType:  "io.coinstack#ValidationFailed",
		ErrorCode:  ValidationFailed,
		StatusCode: 400,
		Message:    "The request could not be processed.",
		Retry:      false,
	},
	// server errors
	InternalServer: {
		ErrorType:  "io.coinstack#InternalServerError",
		ErrorCode:  InternalServer,
		StatusCode: 500,
		Message:    "The server encountered an internal error trying to fulfill the request.",
		Retry:      true,
	},
	ServerUnavailable: {
		ErrorType:  "io.coinstack#ServerUnavailableError",
		ErrorCode:  ServerUnavailable,
		StatusCode: 503,
		Message:    "The service is currently unavailable or busy.",
		Retry:      true,
	},
}

func NewCoinStackError(errorCode int) *CoinStackError {
	prototype, found := coinstackErrors[errorCode]

	if !found {
		return nil
	}

	newError := CoinStackError{}
	newError = prototype
	return &newError
}

func (error *CoinStackError) SetCause(cause string) *CoinStackError {
	error.Cause = cause
	return error
}
