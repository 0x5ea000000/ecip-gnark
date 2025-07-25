package utils

import (
	"filippo.io/edwards25519"
	field25519 "filippo.io/edwards25519/field"
	"log"
	"math/big"
)

func DecompressPoint(pubkey []byte) (xBig, yBig *big.Int, err error) {
	point := new(edwards25519.Point)
	if _, err = point.SetBytes(pubkey); err != nil {
		log.Fatalf("Invalid point: %v", err)
	}

	X, Y, Z, _ := point.ExtendedCoordinates()

	ZInv := new(field25519.Element).Invert(Z)
	x := new(field25519.Element).Multiply(X, ZInv)
	y := new(field25519.Element).Multiply(Y, ZInv)

	xBig = FeToBigInt(x)
	yBig = FeToBigInt(y)

	return
}

func ScalarToBigInt(s *edwards25519.Scalar) *big.Int {
	return new(big.Int).SetBytes(reverse(s.Bytes()))
}

func FeToBigInt(fe *field25519.Element) *big.Int {
	// Convert FieldElement to little-endian bytes, then to big.Int
	return new(big.Int).SetBytes(reverse(fe.Bytes()))
}

func reverse(b []byte) []byte {
	n := len(b)
	res := make([]byte, n)
	for i := 0; i < n; i++ {
		res[i] = b[n-1-i]
	}
	return res
}
