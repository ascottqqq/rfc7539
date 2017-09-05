// implements ChaCha20 using rfc7549 spec (one 32 bit word for counter)
// more details at https://tools.ietf.org/html/rfc7539
// Implementation in Go by Aaron Scott, hereby denoted as
// "the implementer"
// To the extent possible under law, the implementor has waved all
// copyright and related or neighboring rights to the source code
// in this file.
// http://creativecommons.org/publicdomain/zero/1.0/
//
package rfc7539

import "encoding/binary"

type ChaCha20 struct {
	Key       [32]uint8
	Counter   uint32
	Nonce     [12]uint8
	Plaintext []uint8
}

// rotate left
func rol32(a uint32, n uint32) uint32 {
	result := (a >> (32 - (n % 32))) | (a << (n % 32))
	return result
}

func chaChaQuarterRound(a *uint32, b *uint32, c *uint32, d *uint32) {
	*a += *b
	*d ^= *a
	*d = rol32(*d, 16)
	*c += *d
	*b ^= *c
	*b = rol32(*b, 12)
	*a += *b
	*d ^= *a
	*d = rol32(*d, 8)
	*c += *d
	*b ^= *c
	*b = rol32(*b, 7)
}

func chaChaRounds(state [16]uint32) [16]uint32 {
	for i := 0; i < 10; i++ {
		chaChaQuarterRound(&state[0], &state[4], &state[8], &state[12])
		chaChaQuarterRound(&state[1], &state[5], &state[9], &state[13])
		chaChaQuarterRound(&state[2], &state[6], &state[10], &state[14])
		chaChaQuarterRound(&state[3], &state[7], &state[11], &state[15])
		chaChaQuarterRound(&state[0], &state[5], &state[10], &state[15])
		chaChaQuarterRound(&state[1], &state[6], &state[11], &state[12])
		chaChaQuarterRound(&state[2], &state[7], &state[8], &state[13])
		chaChaQuarterRound(&state[3], &state[4], &state[9], &state[14])
	}
	return state
}

func chaChaBlock(key *[32]uint8, counter uint32, nonce *[12]uint8) [16 * 4]uint8 {
	var state [16]uint32

	state[0] = 0x61707865
	state[1] = 0x3320646e
	state[2] = 0x79622d32
	state[3] = 0x6b206574

	for i := 4; i < 12; i++ {
		state[i] = binary.LittleEndian.Uint32(key[(i-4)*4:])
	}
	state[12] = counter
	for i := 13; i < 16; i++ {
		state[i] = binary.LittleEndian.Uint32(nonce[(i-13)*4:])
	}
	workingState := chaChaRounds(state)
	for i := 0; i < 16; i++ {
		workingState[i] = workingState[i] + state[i]
	}
	var result [16 * 4]uint8
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(result[i*4:], workingState[i])
	}
	return result
}

func Encrypt(state *ChaCha20) []uint8 {
	var encryptedMessage []uint8
	for j := uint32(0); j < uint32(len(state.Plaintext)/64); j++ {
		keyStream := chaChaBlock(&state.Key, state.Counter+j, &state.Nonce)
		block := state.Plaintext[(j * 64) : j*64+64]
		for i := 0; i < 64; i++ {
			encryptedMessage = append(encryptedMessage, block[i]^keyStream[i])
		}
	}
	if (len(state.Plaintext) % 64) != 0 {
		j := uint32(len(state.Plaintext) / 64)
		keyStream := chaChaBlock(&state.Key, state.Counter+j, &state.Nonce)
		block := state.Plaintext[j*64 : len(state.Plaintext)]
		for i := 0; i < len(state.Plaintext)%64; i++ {
			encryptedMessage = append(encryptedMessage, block[i]^keyStream[i])
		}
	}
	return encryptedMessage
}

// decrypt is identical algorithm to encrypt, just a wrapper on encrypt
func Decrypt(state *ChaCha20) []uint8 {
	decryptedMessage := Encrypt(state)
	return decryptedMessage
}
