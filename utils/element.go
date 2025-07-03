package utils

import (
	"github.com/consensys/gnark/std/math/emulated"
	"math/big"
)

func ToBigInt[T emulated.FieldParams](element *emulated.Element[T]) (*big.Int, error) {
	var fp T
	bitsPerLimb := fp.BitsPerLimb()

	result := big.NewInt(0)
	base := big.NewInt(1)

	// Element uses little-endian encoding (least significant limb first)
	for _, limb := range element.Limbs {
		// Convert limb to big.Int (assuming it's a constant or can be evaluated)
		limbValue := new(big.Int)
		switch v := limb.(type) {
		case *big.Int:
			limbValue.Set(v)
		case int64:
			limbValue.SetInt64(v)
		case uint64:
			limbValue.SetUint64(v)
			// Add other type conversions as needed
		}

		// Add limb contribution: result += limbValue * base
		temp := new(big.Int).Mul(limbValue, base)
		result.Add(result, temp)

		// Update base for next limb: base *= 2^bitsPerLimb
		base.Lsh(base, uint(bitsPerLimb))
	}

	return result, nil

	//return new(big.Int), nil
}
