package rc4

import (
	"bytes"
	"testing"
)

func TestRC4(t *testing.T) {
	b, err := NewCipher([]byte("SECRET"))
	if err != nil {
		t.Fatal(err)
	}

	in := []byte("This is a test")
	out := make([]byte, len(in))
	b.Encrypt(out, in)

	expect := []byte{200, 6, 5, 12, 47, 73, 80, 232, 131, 70, 200, 214, 18, 118}
	if !bytes.Equal(expect, out) {
		t.Fatal("Incorrect output")
	}
}
