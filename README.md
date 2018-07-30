Coinstack
====
Forked from btcsuite/btcd

Coinstack is a practical and high-performance blockchain platofrm. Coinstack has a simple and convenient development methodology. It is a block-chain platform that provides the performance, scalability, and ease of development that is essential for running next-generation services based on block chains in an enterprise environment.

It has been recognized as a world-class technology by GS certification of ISO international standard. Coinstack is used to provide block chain-based services in various fields such as authentication, finance, and IOT.

#### You can see who made this platform and how many partners are using Coinstack.

[Blocko](https://www.blocko.io/)

#### You can see the detailed use case of real world blockchain business.

[UseCase of Coinstack](https://www.blocko.io/usecase.html)

#### You can see various development documentation in github.

[BlockoDoc](https://github.com/blockodocp)

## Requirements

[Go](http://golang.org) 1.9 or newer.

## Installation

#### Linux/BSD/MacOSX/POSIX - Build from Source

- Install Go according to the installation instructions here:
  http://golang.org/doc/install

- Ensure Go was installed properly and is a supported version:

```bash
$ go version
$ go env GOROOT GOPATH
```

NOTE: The `GOROOT` and `GOPATH` above must not be the same path.  It is
recommended that `GOPATH` is set to a directory in your home directory such as
`~/goprojects` to avoid write permission issues.  It is also recommended to add
`$GOPATH/bin` to your `PATH` at this point.

- Run the following commands to obtain btcd, all dependencies, and install it:

```bash
$ go get -u github.com/Masterminds/glide
$ git clone https://github.com/coinstack/coinstackd $GOPATH/src/github.com/coinstack/coinstackd
$ cd $GOPATH/src/github.com/coinstack/coinstackd
$ glide install
$ go install . ./cmd/...
```

- coinstackd (and utilities) will now be installed in ```$GOPATH/bin```.  If you did
  not already add the bin directory to your system path during Go installation,
  we recommend you do so now.

#### Linux/BSD/MacOSX/POSIX - Build docker image

- Run the following commands to build docker image

```bash
$ cd $GOPATH/src/github.com/coinstack/coinstackd
$ gil pull 
$ ./build.sh
```

## Updating

#### Linux/BSD/MacOSX/POSIX - Build from Source

- Run the following commands to update coinstackd, all dependencies, and install it:

```bash
$ cd $GOPATH/src/github.com/coinstack/coinstackd
$ git pull && glide install
$ go install . ./cmd/...
```

## Getting Started
#### Sample Configuration File
 coinstackd.ini.sample is a sample coinstackd configuration file.  For a detailed overview of all available configuration options, refer to 

```bash 
$ ./coinstackd -h
```

#### Linux/BSD/POSIX/Source
```bash
$ ./coinstackd
````

## Mailing lists

To subscribe to a given list, send email to tech@blocko.io

## Documentation

The documentation is a work-in-progress.  It is located in the [blockodoc](https://github.com/blockodoc?tab=repositories).

Also see coninstack_manual_v0.2_20180726.pdf(Korean version only, English version will support later) in repository


## License

Coinstack is licensed under the [copyfree](http://copyfree.org) ISC License.
