package eddsa

import (
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

func (c *PreHashCircuit[Base, Scalars]) Define(api frontend.API) error {

	//A, _ := new(big.Int).SetString("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec", 0)
	//D, _ := new(big.Int).SetString("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3", 0)
	//Gx, _ := new(big.Int).SetString("0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", 0)
	//Gy, _ := new(big.Int).SetString("0x6666666666666666666666666666666666666666666666666666666666666658", 0)

	err := Verify[Base, Scalars](api, c.Sig, c.Msg, c.Hash, c.Pub)
	if err != nil {
		return err
	}
	return nil
}

func TestPreHashEddsa(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness PreHashCircuit[Fp, Fr]

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

func TestPreHashEddsa2(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness PreHashCircuit[Fp, Fr]

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
