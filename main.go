package main

import (
	"0x5ea000000/ecip-gnark/signature/eddsa"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"filippo.io/edwards25519"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"log"
	"math/big"

	field25519 "filippo.io/edwards25519/field"
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

	err := eddsa.Verify[Base, Scalars](api, c.Sig, c.Msg, c.Hash, c.Pub)
	if err != nil {
		return err
	}
	return nil
}

func main() {
	main1()
	//main2()
}

func Ed25519() {
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

func Ed25519RandomKey() {

}

func DecompressPoint(pubkey []byte) (xBig, yBig *big.Int, err error) {
	point := new(edwards25519.Point)
	if _, err = point.SetBytes(pubkey); err != nil {
		log.Fatalf("Invalid point: %v", err)
	}

	X, Y, Z, _ := point.ExtendedCoordinates()

	ZInv := new(field25519.Element).Invert(Z)
	x := new(field25519.Element).Multiply(X, ZInv)
	y := new(field25519.Element).Multiply(Y, ZInv)

	xBig = feToBigInt(x)
	yBig = feToBigInt(y)

	return
}

func scalarToBigInt(s *edwards25519.Scalar) *big.Int {
	return new(big.Int).SetBytes(reverse(s.Bytes()))
}

func feToBigInt(fe *field25519.Element) *big.Int {
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

func main1() {
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
	sum := h.Sum(nil)
	H, err := edwards25519.NewScalar().SetUniformBytes(sum)
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}

	fmt.Println("msg:", hex.EncodeToString(msg))
	fmt.Println("pubkey (A):", hex.EncodeToString(A))
	fmt.Println("R:", hex.EncodeToString(R))
	fmt.Println("S:", hex.EncodeToString(scalarToBigInt(S).Bytes()))
	fmt.Println("SHA512(R || A || msg):", hex.EncodeToString(sum))
	fmt.Println("H:", hex.EncodeToString(scalarToBigInt(H).Bytes()))

	if !ed25519.Verify(pub, msg, sig) {
		panic("failed to verify signature outside circuit")
	}

	//aa, _ := new(edwards25519.Point).SetBytes(A)
	//rr, _ := new(edwards25519.Point).SetBytes(R)

	aX, aY, _ := DecompressPoint(A)
	rX, rY, _ := DecompressPoint(R)
	fmt.Printf("-------------------------------------------\n")

	fmt.Printf("ax: %x\n", aX)
	fmt.Printf("ay: %x\n", aY)

	fmt.Printf("rx: %x\n", rX)
	fmt.Printf("ry: %x\n", rY)

	fmt.Printf("h: %x\n", scalarToBigInt(H))
	fmt.Printf("s: %x\n", scalarToBigInt(S))

	var circuit, assignment PreHashCircuit[Fp, Fr]

	_r1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(_r1cs)

	assignment.Sig = eddsa.Signature[Fp, Fr]{
		R: sw_emulated.AffinePoint[Fp]{
			X: emulated.ValueOf[Fp](rX),
			Y: emulated.ValueOf[Fp](rY),
		},
		S: emulated.ValueOf[Fr](scalarToBigInt(S)),
	}

	assignment.Msg = emulated.Element[Fr]{}

	assignment.Hash = emulated.ValueOf[Fr](scalarToBigInt(H))

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

func main2() {
	var circuit, assignment PreHashCircuit[Fp, Fr]

	_r1cs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(_r1cs)

	assignment.Sig = eddsa.Signature[Fp, Fr]{
		R: sw_emulated.AffinePoint[Fp]{
			X: emulated.ValueOf[Fp]("0x74CAF2D2E350E3163A7FCAAED6182D8CC49680EBDCFDFFADC4B2393490FF70C8"),
			Y: emulated.ValueOf[Fp]("0x32DA53FEFA270C5AD0ABBC1CE6722B20640F6152BDA5A27DCF5812C6871C7789"),
		},
		S: emulated.ValueOf[Fr]("5004556735901913393272427758925840403246877222315506387332009764265656498271"),
	}

	assignment.Msg = emulated.Element[Fr]{}

	assignment.Hash = emulated.ValueOf[Fr]("1958233733501237659471134851339390337284068724042047466985993338226439154310")

	assignment.Pub = eddsa.PublicKey[Fp, Fr]{
		A: sw_emulated.AffinePoint[Fp]{
			X: emulated.ValueOf[Fp]("0x00AD32A9840941679E3E18FE874961A46EFAFC457E9117926EEBB5D68493E63C"),
			Y: emulated.ValueOf[Fp]("0x3DA446D77C2684FFFD12575C411275EDAA4299F4A7282FD124D0DEC379F55218"),
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

	// verify the proof
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		// invalid proof
	}
}
