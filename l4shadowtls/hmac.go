package l4shadowtls

import (
	"crypto/hmac"
	"crypto/sha1"
	"hash"
)

type ShortHMAC interface {
	hash.Hash
	ShortDigest() [_hmacSize]byte
	Clone() ShortHMAC
}

type shortHMAC struct {
	hash.Hash
	cloneFn func() ShortHMAC
}

var _ hash.Hash = &shortHMAC{}

func newShortHMAC(key string, initData [2][]byte) ShortHMAC {
	h := hmac.New(sha1.New, []byte(key))
	h.Write(initData[0])
	h.Write(initData[1])
	return &shortHMAC{
		Hash: h,
		cloneFn: func() ShortHMAC {
			return newShortHMAC(key, initData)
		},
	}
}

func (h *shortHMAC) ShortDigest() [_hmacSize]byte {
	digest := h.Hash.Sum(nil)
	return [4]byte{digest[0], digest[1], digest[2], digest[3]}
}

func (h *shortHMAC) Clone() ShortHMAC {
	return h.cloneFn()
}
