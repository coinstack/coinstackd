# gengenesis

Generate a new genesis block and encode it in base58 format to serialize.

A private key is required to create a coinbase transaction in the genesis block.
This private key will be used to manage the blockchain starting with the genesis block.


## help

```
Usage:
  gengenesis [OPTIONS]

Application Options:
  -k, --key=  Private key to create genesis block with
  -f, --flag= Coinbase flag to create genesis block with (/P2SH/btcd/)

Help Options:
  -h, --help  Show this help message
```


## e.g.

```
$ gengenesis --key=L4sPydHZTAN8WvzzFNXac7ixtWtQiANTd1V8zGupZNdyV8pfrDRi
```

```
[Chain ID]
CYH8iUTx76WbcNsXXY4vJkXtZCcXcocQKo
[Admin Address]
02a1d5c4181330f459fd2e77ca3e5fdcfa8783cede00a8df90af55f56b0853aff0
[Genesis Block Hash]
0057621049c6f2014b27bc706cef429fa6454206d8c75576c0c86de1f567b2bf
[Serialized Genesis Block]
5c5GRw3Gi38VwSc4CE5rrJmi1w1nqMWokmcuUP1Up3D2jVgf4gWehJxfjPwA6U4KtFBQ99JxhKpkNJbSNEQsrt1C3oSxQcXRaazxYa2NtkTGKkZjY3yY4uXLNaSbEJKUivefgLNegmWxBCj6pVmjsJo5xDAW3VQ7aiJNCbdtRAnFbKhge5FuCrNjHP9dTYSNznVokRkP1TgPdyUsfUNCFq77dCfimQKBxQmqtqzg9PkAm6n5GWDx7Fgvd1cYG35mMaGUCQ32Xq4KP5
```
