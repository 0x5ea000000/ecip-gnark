package utils

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestToBigIntInRange(t *testing.T) {
	str := "115792089237316195423570985008687907853269984665640564039457584007908834671663"

	element := emulated.ValueOf[emulated.Secp256k1Fp](str)
	element.Initialize(ecc.BN254.BaseField())

	bigint, _ := ToBigInt[emulated.Secp256k1Fp](&element)

	assert.Equal(t, str, bigint.String())
}

func TestToBigIntOverflow(t *testing.T) {
	str := "115792089237316195423570985008687907853269984665640564039457584007908834671664"

	element := emulated.ValueOf[emulated.Secp256k1Fp](str)
	element.Initialize(ecc.BN254.BaseField())

	bigint, _ := ToBigInt[emulated.Secp256k1Fp](&element)

	// String representations should not be equal due to overflow
	assert.NotEqual(t, str, bigint.String())

	// But the value should be equal to the original modulo the field modulus
	var fp emulated.Secp256k1Fp
	modulus := fp.Modulus()

	// Parse original string to big.Int
	originalBigInt := new(big.Int)
	originalBigInt.SetString(str, 10)

	// Calculate original mod field modulus
	originalMod := new(big.Int).Mod(originalBigInt, modulus)

	// The bigint from element should equal original mod field modulus
	assert.Equal(t, originalMod.String(), bigint.String())
}
