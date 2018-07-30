// Copyright (c) 2016 BLOCKO INC.
package main

import (
	"bytes"
	"io/ioutil"
	"os/exec"
	"testing"
)

func TestContractctl(t *testing.T) {
	build := exec.Command("/bin/sh", "-c", "go build .")
	err := build.Run()
	if err != nil {
		t.Error(err)
	}
	out, err := exec.Command("/bin/sh", "-c", "./contractctl -d def_test.lua -e exec_test1.lua 2>&1").Output()
	if err == nil {
		t.Error("exit status 0")
	} else if err.Error() != "exit status 1" {
		t.Error(err)
	}
	b, err := ioutil.ReadFile("expected.txt")
	if err != nil {
		t.Error(err)
	}
	if bytes.Compare(out, b) != 0 {
		t.Errorf("\ngot:\n%swant:\n%s", string(out), string(b))
	}
}
