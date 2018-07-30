// Copyright (c) 2016 BLOCKO INC.
package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btclog"

	"github.com/btcsuite/fastsha256"
	"golang.org/x/crypto/pbkdf2"
)

/*******************
 * !!!WARNING!!!
 *******************
 * MUST be cautious when to upgrade Crypto Version.
 * MUST go with Coinstack SDKs.
 * DON'T decrease Crypto Version.
 */
const (
	// CryptoVersion is designated to handle a changing logic
	CryptoVersion = 3
)

/*******************
 * !!!WARNING!!!
 *******************
 * DON'T change constant values.
 * MUST add a new value and type.
 * MUST be same with Coinstack SDKs.
 */
// These constants signify the type of encrypt/decrypt comprehensive method
const (
	// TypeAES256HMAC hash value of password to find out can decrypt or not
	TypeAES256HMAC = 1
	// TypePBKDF2 iterated hash value of password to find out can decrypt or not
	TypeAES256PBKDF2 = 2
	// TypeAES256Simple hash value of password using simple way
	TypeAES256Simple = 3

	// Type NULL no cipher type
	TypeNULL = 0

	/*****************
	 * !!DEPRECATED!!
	 *****************/
	// TypeAES256ANCIENT was provided for KFTC project in 2017 as Crypto Version 1
	//	   However, it has an error when to decrypt an encrypted logic.
	//	   Because of this, new version (>=3) contains a hash value in the encrypted data.
	TypeAES256ANCIENT = -1

	// TypeAES256ANCIENTNoDigest was provided for KFTC project in 2017 as Crypto Version 2
	//	   However, it has an error when to decrypt an encrypted logic.
	//	   Because of this, new version (>=3) contains a hash value in the encrypted data.
	TypeAES256ANCIENTNoDigest = -2
)

// AESBlockSize AES block = 16 bytes
const AESBlockSize = 1 << 4

// SaltSize default salt size
// 2017 NIST guide (sec5.1.1.2) : SALT at least 32 bits
const SaltSize = 32

// PBKDF2IterCnt iteration count of hash function for PBKDF2
// 2017 NIST guide (sec5.1.1.2) : at least 10,000 iterations
const PBKDF2IterCnt = 10000

// AES256KeyLength key length of AES 256
/*
 * 	- AES128 = 16 = 128 bits
 * 	- AES192 = 24 = 192 bits
 * 	- AES256 = 32 = 256 bits
 */
const AES256KeyLength = 32

// DefaultCryptoType default crypto type
const DefaultCryptoType = TypeAES256HMAC

// Crypto the content to encrypt or decrypt
type Crypto struct {
	password []byte
	Version  int
	Type     int
	Salt     []byte
	IV       []byte
	SkHash   []byte
}

// New is to create Crypto instance with a default type
func New(password []byte) *Crypto {
	if log.Level() == btclog.TraceLvl {
		log.Tracef("New: %v",
			base64.StdEncoding.EncodeToString(password))
	}
	log.Tracef("New:%v", password)

	return &Crypto{
		password: password,
		Type:     TypeNULL,
	}
}

// NewWithType is to create Crypto instance with a specific type
func NewWithType(password []byte, tp int) *Crypto {
	if log.Level() == btclog.TraceLvl {
		log.Tracef("NewWithType: %v, %v",
			base64.StdEncoding.EncodeToString(password), tp)
	}

	return &Crypto{
		password: password,
		Type:     tp,
	}
}

// Encrypt provides a consistent method to encrypt a plain bytes
// which is inputted as an argument.
func (crypto *Crypto) Encrypt(pbytes []byte) ([]byte, error) {
	if log.Level() == btclog.TraceLvl {
		log.Tracef("Encrypt: %v",
			base64.StdEncoding.EncodeToString(pbytes))
	}

	if crypto.Type == TypeNULL {
		crypto.Type = DefaultCryptoType
	}

	switch crypto.Type {
	case TypeAES256HMAC:
		if err := crypto.preparePBKDF2(1, AES256KeyLength); err != nil {
			log.Errorf("faile to prepare HMAC: %v", err)
			return nil, err
		}
		return crypto.encryptAES256withCBC(pbytes)
	case TypeAES256PBKDF2:
		if err := crypto.preparePBKDF2(PBKDF2IterCnt, AES256KeyLength); err != nil {
			log.Errorf("faile to prepare PBKDF2: %v", err)
			return nil, err
		}
		return crypto.encryptAES256withCBC(pbytes)
	case TypeAES256Simple:
		if err := crypto.prepareSimple256(); err != nil {
			log.Errorf("faile to prepare Simple: %v", err)
			return nil, err
		}
		return crypto.encryptAES256withCBC(pbytes)
	default:
		return nil, errors.New("unsupported type of encryption")
	}
}

// Decrypt provides a consistent method to decrypt a encrypted bytes
// which is inputted as an argument.
func (crypto *Crypto) Decrypt(encbytes []byte) ([]byte, error) {
	if log.Level() == btclog.TraceLvl {
		log.Tracef("Decrypt: %v",
			base64.StdEncoding.EncodeToString(encbytes))
	}

	ctype, cbytes, err := crypto.prepareDecipher(encbytes)
	if err == nil {
		if log.Level() == btclog.TraceLvl {
			log.Tracef("ctype=%v", ctype)
			log.Tracef("base64(cbytes)=%v", base64.StdEncoding.EncodeToString(cbytes))
		}

		crypto.Type = ctype
		return crypto.decryptAES256withCBC(cbytes)
	}

	return nil, fmt.Errorf("fail to decrypt: %v", err)
}

func (crypto *Crypto) prepareSimple256() error {
	log.Debug("prepareSimple256")

	plen := len(crypto.password)
	if plen > 32 {
		// generate 32 bytes using sha256
		sha256 := fastsha256.New()
		sha256.Write(crypto.password)
		crypto.password = sha256.Sum(nil)
	} else if plen < 32 {
		// use a random salt to pad to fit the password as 32 bytes
		crypto.Salt = make([]byte, 32-plen%32)
		if _, err := rand.Reader.Read(crypto.Salt); err != nil {
			return errors.New("fail to generate a salt")
		}
		crypto.password = append(crypto.password, crypto.Salt...)
	}
	log.Tracef("salt=%v", crypto.Salt)
	log.Tracef("secretkey=%v", crypto.password)

	// prepare IV
	if crypto.IV == nil {
		crypto.IV = make([]byte, AESBlockSize)
		if _, err := rand.Reader.Read(crypto.IV); err != nil {
			return errors.New("fail to generate an initial vector")
		}
	}
	log.Tracef("iv=%v", crypto.IV)

	if plen > 32 {
		// derive hash value to compare the password
		crypto.SkHash = pbkdf2.Key(crypto.password, crypto.Salt, 1, 32, fastsha256.New)
	} else {
		sha256 := fastsha256.New()
		sha256.Write(crypto.password)
		crypto.SkHash = sha256.Sum(nil)
	}
	log.Tracef("skhash=%v", crypto.SkHash)

	return nil
}

func (crypto *Crypto) preparePBKDF2(loop, keylen int) error {
	log.Debugf("preparePBKDF2: %v, %v", loop, keylen)

	// prepare salt
	if crypto.Salt == nil {
		crypto.Salt = make([]byte, SaltSize)
		if _, err := rand.Reader.Read(crypto.Salt); err != nil {
			return errors.New("fail to generate a salt")
		}
	}
	log.Tracef("salt=%v", crypto.Salt)

	// prepare IV
	if crypto.IV == nil {
		crypto.IV = make([]byte, AESBlockSize)
		if _, err := rand.Reader.Read(crypto.IV); err != nil {
			return errors.New("fail to generate an initial vector")
		}
	}
	log.Tracef("iv=%v", crypto.IV)

	// derive hash value to compare the password
	crypto.SkHash = pbkdf2.Key(crypto.password, crypto.Salt, loop, keylen, fastsha256.New)
	log.Tracef("skhash=%v", crypto.SkHash)

	// derive the secret key by sha256 with password and salt
	sha256 := fastsha256.New()
	sha256.Write(crypto.password)
	sha256.Write(crypto.Salt)
	crypto.password = sha256.Sum(nil)
	log.Tracef("secretkey=%v", crypto.password)

	return nil
}

func (crypto *Crypto) encryptAES256withCBC(pbytes []byte) ([]byte, error) {
	log.Debugf("encryptAES256withCBC: %v", pbytes)

	// make padding
	plen := len(pbytes)
	padlen := AESBlockSize - plen%AESBlockSize
	log.Tracef("padlen=%v", padlen)

	// make blocks
	blocks := padBlocksByPKCS7(pbytes, padlen)
	log.Tracef("blocks=%v", blocks)

	// encrypt
	aes256, err := aes.NewCipher(crypto.password)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCEncrypter(aes256, crypto.IV)
	cbc.CryptBlocks(blocks, blocks)

	// get crypto version
	cryptoVer := make([]byte, 4)
	binary.LittleEndian.PutUint32(cryptoVer, uint32(CryptoVersion))
	log.Tracef("cryptoVer=%v", cryptoVer)

	// get type bytes
	tbytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(tbytes, uint32(crypto.Type))
	log.Tracef("tbytes=%v", tbytes)

	// cbytes = crypto_version(4) + type(4) + salt(SaltSize) + skhash(AES256KeyLength) + IV(AESBlockSize) + cipher text
	cbytes := make([]byte, 0, 4+4+SaltSize+AES256KeyLength+AESBlockSize+len(blocks))
	cbytes = append(cbytes, cryptoVer...)     // crypto version
	cbytes = append(cbytes, tbytes...)        // type
	cbytes = append(cbytes, crypto.Salt...)   // salt
	cbytes = append(cbytes, crypto.SkHash...) // secret key hash
	cbytes = append(cbytes, crypto.IV...)     // IV
	cbytes = append(cbytes, blocks...)        // encrypted blocks
	log.Tracef("cbytes=%v", cbytes)

	return cbytes, nil
}

func (crypto *Crypto) prepareDecipher(encbytes []byte) (int, []byte, error) {
	log.Debugf("prepareDecipher: %v", encbytes)

	// strip off crypto version
	if len(encbytes) < 4 {
		return TypeNULL, nil, errors.New("cipher text is improper size: crypto version")
	}
	cryptoVer := int(binary.LittleEndian.Uint32(encbytes[:4]))
	if cryptoVer != CryptoVersion {
		return TypeNULL, nil, fmt.Errorf("unsupported crypto version: %v", cryptoVer)
	}
	crypto.Version = cryptoVer
	log.Tracef("crypto.Version=%v", crypto.Version)
	encbytes = encbytes[4:]

	// strip off type
	if len(encbytes) < 4 {
		return TypeNULL, nil, errors.New("cipher text is improper size: type wrong")
	}
	ctype := int(binary.LittleEndian.Uint32(encbytes[:4]))
	if crypto.Type == TypeNULL {
		crypto.Type = ctype
	}
	log.Tracef("ctype=%v", ctype)

	// verify crypto type
	pwlen := len(crypto.password)
	loop := 0
	keylen := 0
	saltSize := 0
	if crypto.Type == ctype {
		if ctype == TypeAES256HMAC {
			loop = 1
			keylen = AES256KeyLength
			saltSize = SaltSize
		} else if ctype == TypeAES256PBKDF2 {
			loop = PBKDF2IterCnt
			keylen = AES256KeyLength
			saltSize = SaltSize
		} else if ctype == TypeAES256Simple {
			loop = 1
			keylen = AES256KeyLength
			if pwlen < 32 {
				saltSize = 32 - pwlen
			}
		} else {
			return TypeNULL, nil, errors.New("cannot recognize the crypto type")
		}
	} else {
		return TypeNULL, nil, errors.New("different crypto type")
	}
	log.Tracef("loop=%v, keylen=%v", loop, keylen)
	encbytes = encbytes[4:]

	// strip off salt
	if len(encbytes) < saltSize {
		return TypeNULL, nil, errors.New("cipher text is improper size: salt wrong")
	}
	crypto.Salt = encbytes[:saltSize]
	log.Tracef("salt=%v", crypto.Salt)
	encbytes = encbytes[saltSize:]

	// strip off secret key hash
	if len(encbytes) < keylen {
		return TypeNULL, nil, errors.New("cipher text is improper size: skhash wrong")
	}
	crypto.SkHash = encbytes[:keylen]
	log.Tracef("skhash=%v", crypto.SkHash)
	encbytes = encbytes[keylen:]

	var dskhash []byte
	if ctype == TypeAES256Simple {
		if pwlen > 32 {
			// generate 32 bytes using sha256
			sha256 := fastsha256.New()
			sha256.Write(crypto.password)
			crypto.password = sha256.Sum(nil)
		} else if pwlen < 32 {
			// generate 32 bytes with the salt
			crypto.password = append(crypto.password, crypto.Salt...)
			if len(crypto.password) != 32 {
				return TypeNULL, nil, errors.New("password is improper")
			}
		}

		// generate the secret key hash
		if pwlen > 32 {
			// derive hash value to compare the password
			dskhash = pbkdf2.Key(crypto.password, crypto.Salt, 1, 32, fastsha256.New)
		} else {
			sha256 := fastsha256.New()
			sha256.Write(crypto.password)
			dskhash = sha256.Sum(nil)
		}
	} else {
		// generate the secret key hash
		dskhash = pbkdf2.Key(crypto.password, crypto.Salt, loop, keylen, fastsha256.New)

		// derive the secret key by sha256 with password and salt
		sha256 := fastsha256.New()
		sha256.Write(crypto.password)
		sha256.Write(crypto.Salt)
		crypto.password = sha256.Sum(nil)
	}
	log.Tracef("dskhash=%v, secretkey=%v", dskhash, crypto.password)

	// verify the secret key
	if !bytes.Equal(crypto.SkHash, dskhash) {
		log.Debugf("skhash=%v", dskhash)
		return TypeNULL, nil, errors.New("secret key is different")
	}

	// srtip off IV
	if len(encbytes) < AESBlockSize {
		return TypeNULL, nil, errors.New("cipher text is improper size: iv wrong")
	}
	crypto.IV = encbytes[:AESBlockSize]
	log.Tracef("iv=%v", crypto.IV)
	encbytes = encbytes[AESBlockSize:]

	// check rest bytes size is correct
	if len(encbytes)%AESBlockSize != 0 {
		return TypeNULL, nil, errors.New("cipher text is improper size: cblock size wrong")
	}
	return ctype, encbytes, nil
}

func (crypto *Crypto) decryptAES256withCBC(cbytes []byte) ([]byte, error) {
	log.Tracef("decryptAES256withCBC: %v", cbytes)

	// decrypt
	aes256, err := aes.NewCipher(crypto.password)
	if err != nil {
		return nil, err
	}
	cbc := cipher.NewCBCDecrypter(aes256, crypto.IV)
	blocks := make([]byte, len(cbytes))
	cbc.CryptBlocks(blocks, cbytes)

	// PKCS#7 unpad
	return unpadBlocksByPKCS7(blocks)
}

func padBlocksByPKCS7(blocks []byte, padlen int) []byte {
	log.Tracef("padBlocksByPKCS7: %v, %v", blocks, padlen)

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

	return append(blocks, padding...)
}

func unpadBlocksByPKCS7(blocks []byte) ([]byte, error) {
	log.Tracef("unpadBlocksByPKCS7: %v", blocks)

	blocklen := len(blocks)
	padbyte := blocks[blocklen-1]
	padlen := int(padbyte)

	// check padded length is proper
	if padlen <= 0 || padlen > AESBlockSize {
		return nil, errors.New("padded size is improper")
	}

	// check all padded bytes are same value as padlen
	for i := 1; i < padlen; i++ {
		if blocks[blocklen-1-i] != padbyte {
			return nil, errors.New("padding byte is improper")
		}
	}
	log.Tracef("padlen=%v", padlen)
	return blocks[:blocklen-padlen], nil
}

// Encrypt is a static function which makes simple to use.
func Encrypt(pbytes, password []byte) ([]byte, error) {
	log.Tracef("Encrypt: %v, %v", pbytes, password)

	c := New(password)
	return c.Encrypt(pbytes)
}

// Decrypt is a static function which makes simple to use.
func Decrypt(cbytes, password []byte) ([]byte, error) {
	log.Tracef("Decrypt: %v, %v", cbytes, password)

	c := New(password)
	return c.Decrypt(cbytes)
}
