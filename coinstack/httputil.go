// Copyright (c) 2016 BLOCKO INC.
// Package coinstack comes from github.com/coinstack/coinstack-core
// And this httputil.go file comes from core/httputil.go of coinstack-core
package coinstack

import (
	"net/http"
)

type ErrorHandlingRoundTripper struct {
	tr     http.RoundTripper
	Ok     bool
	Status int
}

func (rt *ErrorHandlingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.tr == nil {
		rt.tr = http.DefaultTransport
	}
	res, err := rt.tr.RoundTrip(req)

	rt.Ok = (nil == err)
	if rt.Ok && res != nil {
		rt.Status = res.StatusCode
	}

	return res, err
}
