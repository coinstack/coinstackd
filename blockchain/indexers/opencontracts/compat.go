// Copyright (c) 2016 BLOCKO INC.
package opencontracts

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/coinstack/coinstackd/coinstack/crypto"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// legacyAESBlockSize AES block = 16 bytes = 256 bits
	legacyAESBlockSize = 1 << 4
	// legacyAES256CBCSaltSize default salt size
	legacyAES256CBCSaltSize = 8
	// legacyAES256CBCIVSize default iv size
	legacyAES256CBCIVSize = legacyAESBlockSize
)

// legacyEncryptAES256CBCNoDigest supports legacy encryption
// for contract body version 2.
func legacyEncryptAES256CBCNoDigest(pbytes, password []byte) ([]byte, error) {
	// make password
	// password should be 32 bytes long
	// if less, append a random salt
	// if more, adjust the password
	plen := len(password)
	var pwsalt []byte
	if plen > 32 {
		// keep only 32 bytes the head
		password = password[:32]
	} else if plen < 32 {
		// use a random salt to pad to fit the password as 32 bytes
		pwsalt = make([]byte, 32-plen%32)
		if _, err := rand.Reader.Read(pwsalt); err != nil {
			log.Error("fail to generate a salt.")
		}
		password = append(password, pwsalt...)
	}

	// make 256 size block
	aes256, err := aes.NewCipher(password)
	if err != nil {
		return nil, err
	}

	// get a random IV
	iv := make([]byte, legacyAES256CBCIVSize)
	if _, err := rand.Reader.Read(iv); err != nil {
		log.Error("fail to generate a IV.")
	}

	// make plain text padding
	plen = len(pbytes)
	padlen := legacyAESBlockSize - plen%legacyAESBlockSize
	// PKCS#7 padding
	padding := bytes.Repeat([]byte{byte(padlen)}, padlen)

	// make blocks
	blocks := append(pbytes, padding...)

	// set CBC mode
	cbc := cipher.NewCBCEncrypter(aes256, iv)
	// encrypt
	cbc.CryptBlocks(blocks, blocks)

	// cbytes capacity = salt length + IV length + text length + padding length
	pwsaltLen := 0
	if pwsalt != nil {
		pwsaltLen = len(pwsalt)
	}
	cbytes := make([]byte, 0, pwsaltLen+len(iv)+len(blocks))
	if pwsaltLen > 0 {
		cbytes = append(cbytes, pwsalt...) // password salt
	}
	cbytes = append(cbytes, iv...)     // IV
	cbytes = append(cbytes, blocks...) // encrypted blocks

	return cbytes, nil
}

// legacyDecryptAES256CBCNoDigest supports legacy decryption
// for contract body version 2.
func legacyDecryptAES256CBCNoDigest(cbytes, password []byte) ([]byte, error) {
	// make password
	// password should be 32 bytes long
	// if less, append a random salt
	// if more, adjust the password
	plen := len(password)
	log.Tracef("password(%d)=%v[%v]", plen, string(password), password)

	saltLen := 0
	if plen > 32 {
		// keep only 32 bytes the head
		password = password[:32]
	} else if plen < 32 {
		// strip off a password salt
		pwsalt := cbytes[:32-plen%32]
		password = append(password, pwsalt...)
		saltLen = len(pwsalt)
		log.Tracef("salt(%d)=%v", saltLen, pwsalt)
	}

	// strip off iv
	iv := cbytes[saltLen : saltLen+legacyAES256CBCIVSize]
	log.Tracef("iv(%d)=%v", len(iv), iv)

	// strip off cipher text
	cblocks := cbytes[saltLen+legacyAES256CBCIVSize:]
	if len(cblocks)%legacyAESBlockSize != 0 {
		return nil, errors.New("crypted block size is improper")
	}
	log.Tracef("cblocks(%d)=%v", len(cblocks), cblocks)

	// decrypt
	aes256, err := aes.NewCipher(password)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCDecrypter(aes256, iv)
	blocks := make([]byte, len(cblocks))
	cbc.CryptBlocks(blocks, cblocks)

	// PKCS#7 unpad
	blocklen := len(blocks)
	padbyte := blocks[blocklen-1]
	padlen := int(padbyte)
	if padlen <= 0 || padlen > legacyAESBlockSize {
		return nil, errors.New("padded size is improper")
	}
	for i := 1; i < padlen; i++ {
		if blocks[blocklen-1-i] != padbyte {
			return nil, errors.New("padding byte is improper")
		}
	}
	log.Tracef("pblocks(%d)=%v, padlen=%v", blocklen, blocks, padlen)

	return blocks[:blocklen-padlen], nil
}

// legacyEncryptAES256CBC supports legacy encryption
// for contract body version 1.
func legacyEncryptAES256CBC(pbytes, password []byte) ([]byte, error) {
	// get a random salt
	salt := make([]byte, legacyAES256CBCSaltSize)
	if _, err := rand.Reader.Read(salt); err != nil {
		panic("fail to generate a salt")
	}
	//log.Tracef("salt(%d)=%v", len(salt), hex.EncodeToString(salt))

	// derive the secret key
	// Key Length: AES128=16bytes, AES192=24bytes, AES256=32bytes
	secretKey := pbkdf2.Key([]byte(password), salt, 65536, 32, sha1.New)
	//log.Tracef("secretkey(%d)=%v", len(secretKey), hex.EncodeToString(secretKey))

	// get a random IV
	iv := make([]byte, legacyAES256CBCIVSize)
	if _, err := rand.Reader.Read(iv); err != nil {
		panic("fail to generate a IV.")
	}
	//log.Tracef("iv(%d)=%v", len(iv), hex.EncodeToString(iv))

	// make padding
	plen := len(pbytes)
	padlen := legacyAESBlockSize - plen%legacyAESBlockSize
	// PKCS#5 padding
	/*
		padding := make([]byte, 0, padlen)
		padbyte := byte(padlen & 0xff)
		for i := 0; i < padlen; i++ {
			padding[i] = padbyte
		}
	*/
	// PKCS#7 padding
	padding := bytes.Repeat([]byte{byte(padlen)}, padlen)

	// make blocks
	blocks := append(pbytes, padding...)
	//log.Tracef("pblocks(%d)=%v", len(blocks), blocks)

	// encrypt
	aes256, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCEncrypter(aes256, iv)
	cbc.CryptBlocks(blocks, blocks)
	//log.Tracef("cblocks(%d)=%v", len(blocks), blocks)

	// cbytes capacity = salt length + IV length + text length + padding length
	cbytes := make([]byte, 0, len(salt)+len(iv)+len(blocks))
	cbytes = append(cbytes, salt...)   // salt
	cbytes = append(cbytes, iv...)     // IV
	cbytes = append(cbytes, blocks...) // encrypted blocks

	return cbytes, nil
}

// legacyDecryptAES256CBC supports legacy decryption
// for contract body version 1.
func legacyDecryptAES256CBC(cbytes, password []byte) ([]byte, error) {
	salt := cbytes[:legacyAES256CBCSaltSize]
	log.Tracef("salt(%d)=%v", len(salt), hex.EncodeToString(salt))

	iv := cbytes[legacyAES256CBCSaltSize : legacyAES256CBCSaltSize+legacyAES256CBCIVSize]
	log.Tracef("iv(%d)=%v", len(iv), hex.EncodeToString(iv))

	cblocks := cbytes[legacyAES256CBCSaltSize+legacyAES256CBCIVSize:]
	log.Tracef("cblocks(%d)=%v", len(cblocks), cblocks)
	if len(cblocks)%legacyAESBlockSize != 0 {
		return nil, errors.New("crypted block size is improper")
	}

	// derive the secret key
	// Key Length: AES128=16bytes, AES192=24bytes, AES256=32bytes
	secretKey := pbkdf2.Key(password, salt, 65536, 32, sha1.New)
	log.Tracef("secretkey(%d)=%v", len(secretKey), hex.EncodeToString(secretKey))

	// decrypt
	aes256, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCDecrypter(aes256, iv)
	blocks := make([]byte, len(cblocks))
	cbc.CryptBlocks(blocks, cblocks)
	log.Tracef("pblocks(%d)=%v", len(blocks), blocks)

	// PKCS#7 unpad
	blocklen := len(blocks)
	padbyte := blocks[blocklen-1]
	padlen := int(padbyte)
	if padlen <= 0 || padlen > legacyAESBlockSize {
		return nil, errors.New("padded size is improper")
	}
	for i := 1; i < padlen; i++ {
		if blocks[blocklen-1-i] != padbyte {
			return nil, errors.New("padding byte is improper")
		}
	}
	log.Tracef("padlen=%v", padlen)

	return blocks[:blocklen-padlen], nil
}

func DecodesCompat(argv string, ver int) ([]byte, error) {
	if ver <= 2 {
		return hex.DecodeString(argv)
	}
	return base64.StdEncoding.DecodeString(argv)
}

func DecryptsCompat(encrypted, key []byte, ver int) ([]byte, error) {
	if ver == 1 {
		return legacyDecryptAES256CBC(encrypted, key)
	} else if ver == 2 {
		return legacyDecryptAES256CBCNoDigest(encrypted, key)
	}
	c := crypto.New(key)
	return c.Decrypt(encrypted)
}
