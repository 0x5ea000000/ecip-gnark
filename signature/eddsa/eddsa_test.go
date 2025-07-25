package eddsa

import (
	sha512api "0x5ea000000/ecip-gnark/hash/sha512"
	"0x5ea000000/ecip-gnark/utils"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"filippo.io/edwards25519"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"testing"
)

type Fp = emulated.Curve25519Fp
type Fr = emulated.Curve25519Fr

type PreHashCircuit[Base, Scalars emulated.FieldParams] struct {
	Sig  Signature[Base, Scalars]
	Msg  emulated.Element[Scalars]
	Hash emulated.Element[Scalars]
	Pub  PublicKey[Base, Scalars]
}

type PreHashCircuitWei[Base, Scalars emulated.FieldParams] PreHashCircuit[Base, Scalars]
type PreHashCircuitEd[Base, Scalars emulated.FieldParams] PreHashCircuit[Base, Scalars]

func (c *PreHashCircuitWei[Base, Scalars]) Define(api frontend.API) error {

	//A, _ := new(big.Int).SetString("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec", 0)
	//D, _ := new(big.Int).SetString("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3", 0)
	//Gx, _ := new(big.Int).SetString("0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", 0)
	//Gy, _ := new(big.Int).SetString("0x6666666666666666666666666666666666666666666666666666666666666658", 0)

	config := Config{
		Hasher:  nil,
		FromWei: true,
	}

	err := Verify[Base, Scalars](api, c.Sig, c.Msg, c.Hash, c.Pub, config)
	if err != nil {
		return err
	}
	return nil
}

func (c *PreHashCircuitEd[Base, Scalars]) Define(api frontend.API) error {

	//A, _ := new(big.Int).SetString("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec", 0)
	//D, _ := new(big.Int).SetString("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3", 0)
	//Gx, _ := new(big.Int).SetString("0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", 0)
	//Gy, _ := new(big.Int).SetString("0x6666666666666666666666666666666666666666666666666666666666666658", 0)

	hasher, err := sha512api.New(api)

	config := Config{
		Hasher:  hasher,
		FromWei: false,
	}

	err = Verify[Base, Scalars](api, c.Sig, c.Msg, c.Hash, c.Pub, config)
	if err != nil {
		return err
	}
	return nil
}

func TestPreHashEddsaWithWeiPoint(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness PreHashCircuitWei[Fp, Fr]

	witness.Sig = Signature[Fp, Fr]{
		R: sw_emulated.AffinePoint[Fp]{
			X: emulated.ValueOf[Fp]("0x74CAF2D2E350E3163A7FCAAED6182D8CC49680EBDCFDFFADC4B2393490FF70C8"),
			Y: emulated.ValueOf[Fp]("0x32DA53FEFA270C5AD0ABBC1CE6722B20640F6152BDA5A27DCF5812C6871C7789"),
		},
		S: emulated.ValueOf[Fr]("5004556735901913393272427758925840403246877222315506387332009764265656498271"),
	}

	witness.Msg = emulated.Element[Fr]{}

	witness.Hash = emulated.ValueOf[Fr]("1958233733501237659471134851339390337284068724042047466985993338226439154310")

	witness.Pub = PublicKey[Fp, Fr]{
		A: sw_emulated.AffinePoint[Fp]{
			X: emulated.ValueOf[Fp]("0x00AD32A9840941679E3E18FE874961A46EFAFC457E9117926EEBB5D68493E63C"),
			Y: emulated.ValueOf[Fp]("0x3DA446D77C2684FFFD12575C411275EDAA4299F4A7282FD124D0DEC379F55218"),
		},
	}

	assert.CheckCircuit(&circuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.WithValidAssignment(&witness))
}

func TestPreHashEddsaWithEdPoint(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness PreHashCircuitEd[Fp, Fr]

	witness.Sig = Signature[Fp, Fr]{
		R: sw_emulated.AffinePoint[Fp]{
			X: emulated.ValueOf[Fp]("0x1971d7552fcab2b076ee12a9899b7c534035e6ccc0eb3be5e5791e6c6e0b35a6"),
			Y: emulated.ValueOf[Fp]("0x106200837fa0ef0d81b3f604972f5358a84358a450121d45ecce0903441b6476"),
		},
		S: emulated.ValueOf[Fr]("0xf587c693ceb6f5107242485c9edb93141c35b4f18097d18f21910741ab371d3"),
	}

	witness.Msg = emulated.Element[Fr]{}

	witness.Hash = emulated.ValueOf[Fr]("0xa4a69f5646be65d1cab3a362e9f670a7aaa1a6f0fbefb59da94158bb4eb5e77")

	witness.Pub = PublicKey[Fp, Fr]{
		A: sw_emulated.AffinePoint[Fp]{
			X: emulated.ValueOf[Fp]("0x4429631321064e8ce496395e57b17d394a1b018ccd50ce71cadc4de682d67432"),
			Y: emulated.ValueOf[Fp]("0x65da8b63f982489d8e40adc91c807aed78e4fe23338c0fca2cfe244ad32f2b5d"),
		},
	}

	assert.CheckCircuit(&circuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.WithValidAssignment(&witness))
}

func TestPreHashEddsa(t *testing.T) {
	assert := test.NewAssert(t)

	msg := []byte("")

	// Generate key pair
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	// Sign the message
	sig := ed25519.Sign(priv, msg)
	R := sig[:32]
	S, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if err != nil {
		panic("ed25519: invalid signature")
	}
	A := pub

	h := sha512.New()
	// Precompute H = SHA512(R || A || msg)
	h.Reset()
	h.Write(R)
	h.Write(A)
	h.Write(msg)
	sum := make([]byte, 0, sha512.Size)
	sum = h.Sum(sum)
	H, err := edwards25519.NewScalar().SetUniformBytes(sum)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	fmt.Println("msg:", hex.EncodeToString(msg))
	fmt.Println("pubkey (A):", hex.EncodeToString(A))
	fmt.Println("R:", hex.EncodeToString(R))
	fmt.Println("S:", hex.EncodeToString(utils.ScalarToBigInt(S).Bytes()))
	fmt.Println("SHA512(R || A || msg):", hex.EncodeToString(sum))
	fmt.Println("H:", hex.EncodeToString(utils.ScalarToBigInt(H).Bytes()))

	// Verify outside circuit
	if !ed25519.Verify(pub, msg, sig) {
		panic("failed to verify signature outside circuit")
	}

	minusG := (&edwards25519.Point{}).Negate(edwards25519.NewGeneratorPoint())
	scalars := make([]*edwards25519.Scalar, 2)
	scalars[0] = S
	scalars[1] = H

	points := make([]*edwards25519.Point, 2)
	points[0] = minusG
	points[1], _ = (&edwards25519.Point{}).SetBytes(A)
	RR := (&edwards25519.Point{}).VarTimeMultiScalarMult(scalars, points)
	RR.Negate(RR)

	rrx, rry, _ := utils.DecompressPoint(RR.Bytes())
	fmt.Printf("rrx: %x\n", rrx)
	fmt.Printf("rry: %x\n", rry)

	assert.Equal(R, RR.Bytes(), "failed to verify signature outside circuit manually")

	aX, aY, _ := utils.DecompressPoint(A)
	rX, rY, _ := utils.DecompressPoint(R)
	fmt.Printf("-------------------------------------------\n")

	fmt.Printf("ax: %x\n", aX)
	fmt.Printf("ay: %x\n", aY)

	fmt.Printf("rx: %x\n", rX)
	fmt.Printf("ry: %x\n", rY)

	fmt.Printf("h: %x\n", utils.ScalarToBigInt(H))
	fmt.Printf("s: %x\n", utils.ScalarToBigInt(S))

	var circuit, witness PreHashCircuitEd[Fp, Fr]

	witness.Sig = Signature[Fp, Fr]{
		R: sw_emulated.AffinePoint[Fp]{
			X: emulated.ValueOf[Fp](rX),
			Y: emulated.ValueOf[Fp](rY),
		},
		S: emulated.ValueOf[Fr](utils.ScalarToBigInt(S)),
	}

	witness.Msg = emulated.Element[Fr]{}

	witness.Hash = emulated.ValueOf[Fr](utils.ScalarToBigInt(H))

	witness.Pub = PublicKey[Fp, Fr]{
		A: sw_emulated.AffinePoint[Fp]{
			X: emulated.ValueOf[Fp](aX),
			Y: emulated.ValueOf[Fp](aY),
		},
	}

	assert.CheckCircuit(&circuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.WithValidAssignment(&witness))
}
