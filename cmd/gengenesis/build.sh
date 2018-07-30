#!/bin/bash

cd $(dirname "$0")

BUILD_BASE=$(pwd)
BUILD_NAME=${BUILD_BASE##*/}
BUILD_DATE=$(date '+%Y%m%d')

DIR_TARGET="target"
DIR_BUILD="$DIR_TARGET/$BUILD_NAME-$BUILD_DATE"

function build_target {
	OS=$1
	ARCH=$2
	NAME=$3
	EXTS=${4:+".exe"}

	FILE="$BUILD_NAME-$NAME$EXTS"
	SAVE="$BUILD_NAME-$NAME.tar.gz"

	mkdir -p $DIR_BUILD && \
		CGO_ENABLED=0 GOOS=$OS GOARCH=$ARCH \
			go build -a -installsuffix cgo -o $DIR_BUILD/$FILE *.go && \
		tar -czf $DIR_BUILD/$SAVE -C $DIR_BUILD $FILE && \
		echo "$FILE"
}

build_target "linux" "amd64" "linux64"
build_target "linux" "386" "linux32"
build_target "windows" "amd64" "win64" "exe"
build_target "windows" "386" "win32" "exe"
build_target "darwin" "amd64" "osx64"
