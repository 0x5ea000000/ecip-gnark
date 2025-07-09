package main

import (
	"0x5ea000000/ecip-gnark/signature/eddsa"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"log"
	"math/big"
)

type Fp = emulated.Curve25519Fp
type Fr = emulated.Curve25519Fr

type PreHashCircuit[Base, Scalars emulated.FieldParams] struct {
	Sig  eddsa.Signature[Base, Scalars]
	Msg  emulated.Element[Scalars]
	Hash emulated.Element[Scalars]
	Pub  eddsa.PublicKey[Base, Scalars]
}

func (c *PreHashCircuit[Base, Scalars]) Define(api frontend.API) error {

	//A, _ := new(big.Int).SetString("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec", 0)
	//D, _ := new(big.Int).SetString("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3", 0)
	//Gx, _ := new(big.Int).SetString("0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", 0)
	//Gy, _ := new(big.Int).SetString("0x6666666666666666666666666666666666666666666666666666666666666658", 0)

	err := eddsa.Verify[Base, Scalars](api, c.Sig, c.Msg, c.Hash, c.Pub)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	var circuit, assignment PreHashCircuit[Fp, Fr]

	r1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(r1cs)

	rx, _ := new(big.Int).SetString("0x74CAF2D2E350E3163A7FCAAED6182D8CC49680EBDCFDFFADC4B2393490FF70C8", 0)
	ry, _ := new(big.Int).SetString("0x32DA53FEFA270C5AD0ABBC1CE6722B20640F6152BDA5A27DCF5812C6871C7789", 0)

	pubx, _ := new(big.Int).SetString("0x00AD32A9840941679E3E18FE874961A46EFAFC457E9117926EEBB5D68493E63C", 0)
	puby, _ := new(big.Int).SetString("0x3DA446D77C2684FFFD12575C411275EDAA4299F4A7282FD124D0DEC379F55218", 0)

	assignment.Sig = eddsa.Signature[Fp, Fr]{
		R: sw_emulated.AffinePoint[Fp]{
			X: emulated.ValueOf[Fp](rx),
			Y: emulated.ValueOf[Fp](ry),
		},
		S: emulated.ValueOf[Fr]("5004556735901913393272427758925840403246877222315506387332009764265656498271"),
	}

	assignment.Msg = emulated.Element[Fr]{}

	assignment.Hash = emulated.ValueOf[Fr]("1958233733501237659471134851339390337284068724042047466985993338226439154310")

	assignment.Pub = eddsa.PublicKey[Fp, Fr]{
		A: sw_emulated.AffinePoint[Fp]{
			X: emulated.ValueOf[Fp](pubx),
			Y: emulated.ValueOf[Fp](puby),
		},
	}

	// witness
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := witness.Public()
	// generate the proof
	proof, err := groth16.Prove(r1cs, pk, witness)

	// verify the proof
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		// invalid proof
	}

}

func RunEd25519() {
	// Provided data
	publicKeyHex := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	signatureHex := "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
	message := []byte("")

	// Decode public key and signature
	publicKey, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		log.Fatalf("Failed to decode public key: %v", err)
	}

	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		log.Fatalf("Failed to decode signature: %v", err)
	}

	// Verify the signature
	valid := ed25519.Verify(publicKey, message, signature)
	if valid {
		fmt.Println("✅ Signature is valid!")
	} else {
		fmt.Println("❌ Signature is invalid.")
	}

}
