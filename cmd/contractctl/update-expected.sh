#!/bin/bash

go build .
./contractctl -d def_test.lua -e exec_test1.lua > expected.log 2>&1
