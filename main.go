package main

import (
	"0x5ea000000/ecip-gnark/signature/eddsa"
	"0x5ea000000/ecip-gnark/utils"
	"crypto/ed25519"
	"crypto/sha512"
	"filippo.io/edwards25519"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type Fp = emulated.Curve25519Fp
type Fr = emulated.Curve25519Fr

type PreHashCircuit[Base, Scalars emulated.FieldParams] struct {
	Sig  eddsa.Signature[Base, Scalars] `gnark:"public"`
	Msg  emulated.Element[Scalars]      `gnark:"public"`
	Hash emulated.Element[Scalars]      `gnark:"public"`
	Pub  eddsa.PublicKey[Base, Scalars] `gnark:"public"`
}

func (c *PreHashCircuit[Base, Scalars]) Define(api frontend.API) error {

	//A, _ := new(big.Int).SetString("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec", 0)
	//D, _ := new(big.Int).SetString("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3", 0)
	//Gx, _ := new(big.Int).SetString("0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", 0)
	//Gy, _ := new(big.Int).SetString("0x6666666666666666666666666666666666666666666666666666666666666658", 0)

	config := eddsa.Config{
		Hasher:  nil,
		FromWei: false,
	}

	err := eddsa.Verify[Base, Scalars](api, c.Sig, c.Msg, c.Hash, c.Pub, config)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	main1()
	//main2()
}

func main1() {
	msg := []byte("lmao")

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

	hasher := sha512.New()
	// Precompute H = SHA512(R || A || msg)
	hasher.Reset()
	hasher.Write(R)
	hasher.Write(A)
	hasher.Write(msg)
	sum := hasher.Sum(nil)
	H, err := edwards25519.NewScalar().SetUniformBytes(sum)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	if !ed25519.Verify(pub, msg, sig) {
		panic("failed to verify signature outside circuit")
	}

	aX, aY, _ := utils.DecompressPoint(A)
	rX, rY, _ := utils.DecompressPoint(R)
	h := utils.ScalarToBigInt(H)
	s := utils.ScalarToBigInt(S)

	var circuit, assignment PreHashCircuit[Fp, Fr]

	_r1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(_r1cs)

	assignment.Sig = eddsa.Signature[Fp, Fr]{
		R: sw_emulated.AffinePoint[Fp]{
			X: emulated.ValueOf[Fp](rX),
			Y: emulated.ValueOf[Fp](rY),
		},
		S: emulated.ValueOf[Fr](s),
	}

	assignment.Msg = emulated.Element[Fr]{}

	assignment.Hash = emulated.ValueOf[Fr](h)

	assignment.Pub = eddsa.PublicKey[Fp, Fr]{
		A: sw_emulated.AffinePoint[Fp]{
			X: emulated.ValueOf[Fp](aX),
			Y: emulated.ValueOf[Fp](aY),
		},
	}

	// witness
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	// generate the proof
	proof, err := groth16.Prove(_r1cs, pk, witness)
	if err != nil {
		panic(err)
	}
	// verify the proof
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
}
