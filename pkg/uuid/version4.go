package uuid

import (
	"crypto/rand"
	"io"
)

type UUID [16]byte

func V4() UUID {
	var uuid UUID

	_, err := io.ReadFull(rand.Reader, uuid[:])
	if err != nil {
		panic(err)
	}

	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant is 10

	return uuid
}
