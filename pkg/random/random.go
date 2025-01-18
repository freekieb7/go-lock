package random

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

func NewBytes(length int) []byte {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return bytes
}

func NewString(length int) string {
	return hex.EncodeToString(NewBytes(length))
}

func NewUrlSafeString(length int) string {
	return base64.URLEncoding.EncodeToString(NewBytes(length))
}
