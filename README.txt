A go implementaton of ChaCha20 as described in rfc7539

result is a []uint8 that is the ciphertext

example of usage:

package main

import (
	"fmt"
	"github.com/ascottqqq/rfc7539"
)

func main() {
	fmt.Println(rfc7539.Encrypt(rfc7539.ChaCha20{[32]uint8{0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00}, 0, [12]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, []byte("Hello world")})
}