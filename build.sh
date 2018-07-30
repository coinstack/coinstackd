#!/bin/bash

COMMIT=`git rev-parse HEAD`
TAG=${1:-3sp2}

sudo docker build --build-arg COMMIT="${COMMIT:0:7}" -t blocko/coinstackd:${TAG} .
