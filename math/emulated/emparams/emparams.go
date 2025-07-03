package emparams

import "math/big"

// Curve25519Fp provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed (base 16)
//	57896044618658097711785492504343953926634992332820282019728792003956564819949 (base 10)
//
// This is the base field of the Curve25519 curve.
type Curve25519Fp struct{}

func (Curve25519Fp) NbLimbs() uint     { return 4 }
func (Curve25519Fp) BitsPerLimb() uint { return 64 }
func (Curve25519Fp) IsPrime() bool     { return true }

func (Curve25519Fp) Modulus() *big.Int {
	var modulus *big.Int

	modulus, _ = new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)

	return modulus
}

// Curve25519Fr provides type parametrization for field emulation:
//   - limbs: 4
//   - limb width: 64 bits
//
// The prime modulus for type parametrisation is:
//
//	0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed (base 16)
//	7237005577332262213973186563042994240857116359379907606001950938285454250989 (base 10)
//
// This is the scalar field of the Curve25519 curve.
type Curve25519Fr struct{}

func (Curve25519Fr) NbLimbs() uint     { return 4 }
func (Curve25519Fr) BitsPerLimb() uint { return 64 }
func (Curve25519Fr) IsPrime() bool     { return true }

func (Curve25519Fr) Modulus() *big.Int {
	var modulus *big.Int

	modulus, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

	return modulus
}
