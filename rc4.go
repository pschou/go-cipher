// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package rc4 implements RC4 encryption, as defined in Bruce Schneier's
// Applied Cryptography.
//
// RC4 is cryptographically broken and should not be used for secure
// applications.
package rc4

import (
	"crypto/cipher"
	"strconv"
	"unsafe"
)

// A rc4Cipher is an instance of RC4 using a particular key.
type rc4Cipher struct {
	s    [256]uint32
	i, j uint8
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/rc4: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new Cipher. The key argument should be the
// RC4 key, at least 1 byte and at most 256 bytes.
func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	if k < 1 || k > 256 {
		return nil, KeySizeError(k)
	}
	var c rc4Cipher
	for i := 0; i < 256; i++ {
		c.s[i] = uint32(i)
	}
	var j uint8 = 0
	for i := 0; i < 256; i++ {
		j += uint8(c.s[i]) + key[i%k]
		c.s[i], c.s[j] = c.s[j], c.s[i]
	}
	return &c, nil
}

// Reset zeros the key data and makes the Cipher unusable.
//
// Deprecated: Reset can't guarantee that the key will be entirely removed from
// the process's memory.
func (c *rc4Cipher) Reset() {
	for i := range c.s {
		c.s[i] = 0
	}
	c.i, c.j = 0, 0
}

func (c *rc4Cipher) BlockSize() int { return 1 }

func (c *rc4Cipher) Decrypt(dst, src []byte) {
	c.XORKeyStream(dst, src)
}

func (c *rc4Cipher) Encrypt(dst, src []byte) {
	c.XORKeyStream(dst, src)
}

// XORKeyStream sets dst to the result of XORing src with the key stream.
// Dst and src must overlap entirely or not at all.
func (c *rc4Cipher) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	if inexactOverlap(dst[:len(src)], src) {
		panic("crypto/rc4: invalid buffer overlap")
	}
	i, j := c.i, c.j
	_ = dst[len(src)-1]
	dst = dst[:len(src)] // eliminate bounds check from loop
	for k, v := range src {
		i += 1
		x := c.s[i]
		j += uint8(x)
		y := c.s[j]
		c.s[i], c.s[j] = y, x
		dst[k] = v ^ uint8(c.s[uint8(x+y)])
	}
	c.i, c.j = i, j
}

// AnyOverlap reports whether x and y share memory at any (not necessarily
// corresponding) index. The memory beyond the slice length is ignored.
func anyOverlap(x, y []byte) bool {
	return len(x) > 0 && len(y) > 0 &&
		uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}

// InexactOverlap reports whether x and y share memory at any non-corresponding
// index. The memory beyond the slice length is ignored. Note that x and y can
// have different lengths and still not have any inexact overlap.
//
// InexactOverlap can be used to implement the requirements of the crypto/cipher
// AEAD, Block, BlockMode and Stream interfaces.
func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	return anyOverlap(x, y)
}
