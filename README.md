# go-rc4

This package is forked from golang.org/x/crypto/rc4, which does not implement
the crypto.Block.  A basic reformat to allow the rest of the Block and
BlockMode to work properly.

This library is made available for convenience and backwards compatibility.


# Example
```
func TestRC4(t *testing.T) {
  b, err := rc4.NewCipher([]byte("SECRET"))
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
```
