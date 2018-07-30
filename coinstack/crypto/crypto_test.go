// Copyright (c) 2016 BLOCKO INC.
package crypto_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"github.com/coinstack/coinstackd/coinstack/crypto"
	"github.com/btcsuite/btclog"
	"github.com/btcsuite/seelog"
)

var (
	bckndlog = seelog.Disabled
	logger   = btclog.Disabled
)

func TestDecryptCBytes(t *testing.T) {
	password := []byte("abcdefg12345^&*()")
	base64ctxts := []string{
		"AwAAAAMAAADwTYjH0DkZ6Fgk/5DJdH6XL57/H7bAiJx7xs5T3DFmr7pTq/hw/YCwdW1FFhr94lhZylUUp7V3b+7XKtRYj93zGoa44hSe1i1F4K7slu4rMg74F7cxxMPtBtxMWAD0s9I2U45DJ/zpfr2znKRjsrqc9jTf6WgBnah7ykvhnGPK",
		"AwAAAAEAAAAO5oeDmTBy3r6BERSunRvYS9N2CdFCr7T8DH8LiTTHAbm5FlGGMezPZx0lbGtvR+nHJBN/9geDdS2wyT/I1Xm4Zh/s2RGQC4pM0QaoNJcFrqTNEnKKTh/QyBBuSCuz2iAoc/vUowTJeD4HSgoDtIe0dfo1qKLygezqKOqWL8aYCRuUPC6V292SAn7b3ve5UR580TmcvZwDwIwPp+fmPTcS",
		"AwAAAAMAAABTTkiydUNXnqf9youYcY3lkb9GRNTxP4Tr4uS56dL2N/tfG4+X2in9Jr0VvSMdHs9ThPR8VQ/586SlCviWM1awMGnOPjs2had+nGecMHuqd++vKo2vJ3oGRRbllTFmkLwL8qsjCvjLbG5dP5NuuP8HbpL0myJHJl9wtoDvcgsO",
		"AwAAAAEAAACmCSqlljlnHaHeUiemht5AJkubVczl3qZ3pd/C6FqbMNQaT37ZfkPoaVJsiMBFEj7dj3Q7pQFXmfqyd9MyxQukT7gOC+lPc/659qR2fLwu35d43wZIif+ndSZvFr4QbLv4wiz2lqZUx1YoOi503nPAmXBKrot8U5bVE8YDHGqSjsHy1O9HsWVtwVcmig6vsK5u3C0wByB6HdHP216/Ybpk",
	}
	var cbytesArr = make([][]byte, len(base64ctxts))
	for i := 0; i < len(base64ctxts); i++ {
		cbytesArr[i], _ = base64.StdEncoding.DecodeString(base64ctxts[i])
	}

	var c *crypto.Crypto
	for i := 0; i < len(cbytesArr); i++ {
		c = crypto.New(password)
		pbytes, err := c.Decrypt(cbytesArr[i])
		if err != nil {
			t.Fatalf("[%d]: %v", i, err)
		}

		switch c.Type {
		case crypto.TypeAES256HMAC:
			t.Logf("[%d] Defaut Crypto Type is AES256 with HMAC", i)
		case crypto.TypeAES256PBKDF2:
			t.Logf("[%d] Defaut Crypto Type is AES256 with PBKDF2", i)
		case crypto.TypeAES256Simple:
			t.Logf("[%d] Defaut Crypto Type is simple AES256", i)
		default:
			t.Fatalf("[%d] unsupported crypto type", i)
		}
		ptxt := string(pbytes)
		t.Logf("ptxt: %v", ptxt)
	}
}

func TestAES256Default(t *testing.T) {
	plainTxt := "Hi. This is an arbitrary plain text to test 'crypto' package of 'coinstack'."
	plainTxtB := []byte(plainTxt)
	password := "abcdefg12345^&*()"

	// Encrypt
	c := crypto.New([]byte(password))
	cbytes, err := c.Encrypt(plainTxtB)
	if err != nil {
		t.Fatal(err)
	}
	cryptoType := crypto.TypeNULL
	switch c.Type {
	case crypto.TypeAES256HMAC:
		t.Logf("Defaut Crypto Type is AES256 with HMAC")
		cryptoType = crypto.TypeAES256HMAC
	case crypto.TypeAES256PBKDF2:
		t.Logf("Defaut Crypto Type is AES256 with PBKDF2")
		cryptoType = crypto.TypeAES256PBKDF2
	case crypto.TypeAES256Simple:
		t.Logf("Defaut Crypto Type is simple AES256")
		cryptoType = crypto.TypeAES256Simple
	default:
		t.Fatal("unsupported crypto type")
	}
	salt := c.Salt
	iv := c.IV
	secretKeyHash := c.SkHash

	base64cbytes := base64.StdEncoding.EncodeToString(cbytes)
	t.Logf("base64(cbytes)=%v", base64cbytes)

	// Decrypt
	c = crypto.New([]byte(password))
	pbytes, err := c.Decrypt(cbytes)
	if err != nil {
		t.Fatal(err)
	}

	// check type
	if c.Type != cryptoType {
		t.Fatal("wrong crypto type")
	}
	// check salt
	if !bytes.Equal(c.Salt, salt) {
		t.Fatal("wrong salt")
	}
	// check iv
	if !bytes.Equal(c.IV, iv) {
		t.Fatal("wrong iv")
	}
	// check secret key hash
	if !bytes.Equal(c.SkHash, secretKeyHash) {
		t.Fatal("wrong secret key hash")
	}

	ptxt := string(pbytes)
	t.Logf("decrypted text = %v", ptxt)
}

func TestAES256Simple(t *testing.T) {
	plainTxt := "Hi. This is an arbitrary plain text to test 'crypto' package of 'coinstack'."
	plainTxtB := []byte(plainTxt)
	password := "abcdefg12345^&*()"
	pwbytes := []byte(password)

	// Encrypt
	c := crypto.NewWithType(pwbytes, crypto.TypeAES256Simple)
	cbytes, err := c.Encrypt(plainTxtB)
	if err != nil {
		t.Fatal(err)
	}
	salt := c.Salt
	iv := c.IV
	secretKeyHash := c.SkHash

	base64cbytes := base64.StdEncoding.EncodeToString(cbytes)
	t.Logf("base64(cbytes)=%v", base64cbytes)

	// Decrypt
	c = crypto.New([]byte(password))
	pbytes, err := c.Decrypt(cbytes)
	if err != nil {
		t.Fatal(err)
	}

	// check type
	if c.Type != crypto.TypeAES256Simple {
		t.Fatal("wrong crypto type")
	}
	// check salt
	if !bytes.Equal(c.Salt, salt) {
		t.Fatal("wrong salt")
	}
	// check iv
	if !bytes.Equal(c.IV, iv) {
		t.Fatal("wrong iv")
	}
	// check secret key hash
	if !bytes.Equal(c.SkHash, secretKeyHash) {
		t.Fatal("wrong secret key hash")
	}

	ptxt := string(pbytes)
	t.Logf("decrypted text = %v", ptxt)
}

func TestAES256PBKDF2(t *testing.T) {
	plainTxt := "Hi. This is an arbitrary plain text to test 'crypto' package of 'coinstack'."
	plainTxtB := []byte(plainTxt)
	password := "abcdefg12345^&*()"

	// Encrypt
	c := crypto.NewWithType([]byte(password), crypto.TypeAES256PBKDF2)
	cbytes, err := c.Encrypt(plainTxtB)
	if err != nil {
		t.Fatal(err)
	}
	salt := c.Salt
	iv := c.IV
	secretKeyHash := c.SkHash

	base64cbytes := base64.StdEncoding.EncodeToString(cbytes)
	t.Logf("base64(cbytes)=%v", base64cbytes)

	// Decrypt
	c = crypto.New([]byte(password))
	pbytes, err := c.Decrypt(cbytes)
	if err != nil {
		t.Fatal(err)
	}

	// check type
	if c.Type != crypto.TypeAES256PBKDF2 {
		t.Fatal("wrong crypto type")
	}
	// check salt
	if !bytes.Equal(c.Salt, salt) {
		t.Fatal("wrong salt")
	}
	// check iv
	if !bytes.Equal(c.IV, iv) {
		t.Fatal("wrong iv")
	}
	// check secret key hash
	if !bytes.Equal(c.SkHash, secretKeyHash) {
		t.Fatal("wrong secret key hash")
	}

	ptxt := string(pbytes)
	t.Logf("decrypted text = %v", ptxt)
}

func TestAES256HMAC(t *testing.T) {
	plainTxt := "Hi. This is an arbitrary plain text to test 'crypto' package of 'coinstack'."
	plainTxtB := []byte(plainTxt)
	password := "abcdefg12345^&*()"

	// Encrypt
	c := crypto.NewWithType([]byte(password), crypto.TypeAES256HMAC)
	cbytes, err := c.Encrypt(plainTxtB)
	if err != nil {
		t.Fatal(err)
	}
	salt := c.Salt
	iv := c.IV
	secretKeyHash := c.SkHash

	base64cbytes := base64.StdEncoding.EncodeToString(cbytes)
	t.Logf("base64(cbytes)=%v", base64cbytes)

	// Decrypt
	c = crypto.New([]byte(password))
	pbytes, err := c.Decrypt(cbytes)
	if err != nil {
		t.Fatal(err)
	}

	// check type
	if c.Type != crypto.TypeAES256HMAC {
		t.Fatal("wrong crypto type")
	}
	// check salt
	if !bytes.Equal(c.Salt, salt) {
		t.Fatal("wrong salt")
	}
	// check iv
	if !bytes.Equal(c.IV, iv) {
		t.Fatal("wrong iv")
	}
	// check secret key hash
	if !bytes.Equal(c.SkHash, secretKeyHash) {
		t.Fatal("wrong secret key hash")
	}

	ptxt := string(pbytes)
	t.Logf("decrypted text = %v", ptxt)
}

func TestMain(m *testing.M) {
	bckndlog, err := seelog.LoggerFromConfigAsString(`
<seelog type="adaptive" mininterval="2000000" maxinterval="100000000"
	critmsgcount="500" minlevel="trace">
	<outputs formatid="all">
		<console />
	</outputs>
	<formats>
		<format id="all" format="%Time %Date [%LEV] %Msg%n" />
	</formats>
</seelog>
		`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fail to initialize logger: %v", err)
		os.Exit(-1)
	}
	defer bckndlog.Flush()

	logger = btclog.NewSubsystemLogger(bckndlog, "CRYPTO_TEST: ")
	//logger.SetLevel(btclog.TraceLvl)
	logger.SetLevel(btclog.Off)

	// set logger
	crypto.UseLogger(logger)

	os.Exit(m.Run())
}

/*************************
 * In history, Crypto Version 1 is provided for KFTC project in 2017
 * However, this logic has an error when to decrypt a encrypted message,
 * so it was deprecated.
 */
func TestAncientVersion1(t *testing.T) {
	plainTxt := "Hi. This is an arbitrary plain text to test 'crypto' package of 'coinstack'."
	plainTxtB := []byte(plainTxt)
	password := []byte("abcdefg12345^&*()")

	// Encrypt
	c := crypto.NewWithType(password, crypto.TypeAES256ANCIENT)
	_, err := c.Encrypt(plainTxtB)
	// should be error
	if err == nil {
		t.Fail()
	}
	t.Log(err)

	// Decrypt
	cbytes, _ := base64.StdEncoding.DecodeString("j59UDrjNsOGcAjq83pz987uMYDWmvuBgyS0r9M5IDssNTwVISKZOTbF/34LZdDo+HYHWahYls2Wkw/cE2RBMCLOMoBAZO5wp7D1kLZk0bQEbPsjvMy97cAPNK8OyU2svrlyg8xl8ELo=")
	_, err = c.Decrypt(cbytes)
	if err == nil {
		t.Fail()
	}
	t.Log(err)
}

/*************************
 * In history, Crypto Version 2 is provided for KFTC project in 2017
 * However, this logic has an error when to decrypt a encrypted message,
 * so it was deprecated.
 */
func TestAncientVersion2(t *testing.T) {
	plainTxt := "Hi. This is an arbitrary plain text to test 'crypto' package of 'coinstack'."
	plainTxtB := []byte(plainTxt)
	password := []byte("abcdefg12345^&*()")

	// Encrypt
	c := crypto.NewWithType(password, crypto.TypeAES256ANCIENTNoDigest)
	_, err := c.Encrypt(plainTxtB)
	// should be error
	if err == nil {
		t.Fail()
	}
	t.Log(err)

	// Decrypt
	cbytes, _ := base64.StdEncoding.DecodeString("j59UDrjNsOGcAjq83pz987uMYDWmvuBgyS0r9M5IDssNTwVISKZOTbF/34LZdDo+HYHWahYls2Wkw/cE2RBMCLOMoBAZO5wp7D1kLZk0bQEbPsjvMy97cAPNK8OyU2svrlyg8xl8ELo=")
	_, err = c.Decrypt(cbytes)
	if err == nil {
		t.Fail()
	}
	t.Log(err)
}
