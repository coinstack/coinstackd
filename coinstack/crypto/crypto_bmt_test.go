// Copyright (c) 2016 BLOCKO INC.
package crypto_test

import (
	"testing"

	"github.com/coinstack/coinstackd/coinstack/crypto"
)

var bmtPlainTxtB = []byte("this is a plain text to benchmark test")

var (
	pw32    = []byte("12345678901234567890123456789012")
	pwShort = []byte("abc")
	pwLong  = []byte("1234567890123456789012345678901234567890abc")
)

/*****
 * How To Benchmark
 * $ go test -bench . -benchtime 1s
 *
 * The fastest method is 'Simple', but also the weakest.
 */

func BenchmarkEnc32byAES256withHMAC(b *testing.B) {
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		c := crypto.NewWithType(pw32, crypto.TypeAES256HMAC)
		c.Encrypt(bmtPlainTxtB)
	}
}

func BenchmarkEncShortbyAES256withHMAC(b *testing.B) {
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		c := crypto.NewWithType(pwShort, crypto.TypeAES256HMAC)
		c.Encrypt(bmtPlainTxtB)
	}
}

func BenchmarkEncLongbyAES256withHMAC(b *testing.B) {
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		c := crypto.NewWithType(pwLong, crypto.TypeAES256HMAC)
		c.Encrypt(bmtPlainTxtB)
	}
}

func BenchmarkEnc32byAES256withPBKDF2(b *testing.B) {
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		c := crypto.NewWithType(pw32, crypto.TypeAES256PBKDF2)
		c.Encrypt(bmtPlainTxtB)
	}
}

func BenchmarkEncShortbyAES256withPBKDF2(b *testing.B) {
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		c := crypto.NewWithType(pwShort, crypto.TypeAES256PBKDF2)
		c.Encrypt(bmtPlainTxtB)
	}
}

func BenchmarkEncLongbyAES256withPBKDF2(b *testing.B) {
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		c := crypto.NewWithType(pwLong, crypto.TypeAES256PBKDF2)
		c.Encrypt(bmtPlainTxtB)
	}
}

func BenchmarkEnc32bySimpleAES256(b *testing.B) {
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		c := crypto.NewWithType(pw32, crypto.TypeAES256Simple)
		c.Encrypt(bmtPlainTxtB)
	}
}

func BenchmarkEncShortbySimpleAES256(b *testing.B) {
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		c := crypto.NewWithType(pwShort, crypto.TypeAES256Simple)
		c.Encrypt(bmtPlainTxtB)
	}
}

func BenchmarkEncLongbySimpleAES256(b *testing.B) {
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		c := crypto.NewWithType(pwLong, crypto.TypeAES256Simple)
		c.Encrypt(bmtPlainTxtB)
	}
}
