package eddsa

import (
	"0x5ea000000/ecip-gnark/curves/emulated/twistededwards"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"math/big"
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

	A, _ := new(big.Int).SetString("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec", 0)
	D, _ := new(big.Int).SetString("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3", 0)
	Gx, _ := new(big.Int).SetString("0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", 0)
	Gy, _ := new(big.Int).SetString("0x6666666666666666666666666666666666666666666666666666666666666658", 0)

	params := twistededwards.CurveParams{
		A:  A,
		D:  D,
		Gx: Gx,
		Gy: Gy,
	}

	err := Verify[Base, Scalars](api, params, c.Sig, c.Msg, c.Hash, c.Pub)
	if err != nil {
		return err
	}
	////field, _ := emulated2.NewField[emulated.Curve25519Fp](api)
	//
	////negGx := emulated2.ValueOf[emulated.Curve25519Fp]("1200667937533468597173217512333411191636182289901409237863732418752693333813")
	////negGy := emulated2.ValueOf[emulated.Curve25519Fp]("39000908319805937285569583676637196217272523591685916771419075934605068722905")
	//
	//negx, _ := new(big.Int).SetString("0x2a78dd0fd02c0339f00b8f02f1c20618a9c13fdf0d617c9aca55c89b025aef35", 0)
	//negy, _ := new(big.Int).SetString("0x5639bb5a38e25dd141b7c45a9c867cdc30902f9e7f8ece9a6487cf0c09d3e2d9", 0)
	//
	//negG := sw_emulated.AffinePoint[emulated.Curve25519Fp]{
	//	X: emulated2.ValueOf[emulated.Curve25519Fp](negx),
	//	Y: emulated2.ValueOf[emulated.Curve25519Fp](negy),
	//}
	//
	//curve, _ := sw_emulated.New[emulated.Curve25519Fp, emulated.Curve25519Fr](api, shortweierstrasses.GetWei25519Params())
	//
	//G := curve.Neg(&negG)
	////G = curve.Neg(G)
	////negGxstr, _ := utils.ToBigInt[emulated.Curve25519Fp](&negGx)
	////negGystr, _ := utils.ToBigInt[emulated.Curve25519Fp](&negGy)
	////fmt.Printf("neg gx: %s\n", negGxstr.String())
	////fmt.Printf("neg gy: %s\n", negGystr.String())
	//
	//Gxstr, _ := utils.ToBigInt[emulated.Curve25519Fp](&negG.X)
	//Gystr, _ := utils.ToBigInt[emulated.Curve25519Fp](&negG.Y)
	//fmt.Printf("neg wei gx: %s\n", Gxstr.String())
	//fmt.Printf("neg wei gy: %s\n", Gystr.String())
	//
	//Gxstr, _ = utils.ToBigInt[emulated.Curve25519Fp](&G.X)
	//Gystr, _ = utils.ToBigInt[emulated.Curve25519Fp](&G.Y)
	//fmt.Printf("raw wei gx: %s\n", Gxstr.String())
	//fmt.Printf("raw wei gy: %s\n", Gystr.String())
	//
	//params := twistededwards.CurveParams{
	//	A:  A,
	//	D:  D,
	//	Gx: Gx,
	//	Gy: Gy,
	//}
	//
	//cr, _ := twistededwards.New[emulated.Curve25519Fp, emulated.Curve25519Fr](api, params)
	//
	//g := cr.Generator()
	//
	//fmt.Println(g)
	//
	//weiG := cr.ToWeierstrassPoint(g)
	//
	//fmt.Println(weiG)
	//
	//xStr, _ := utils.ToBigInt[emulated.Curve25519Fp](&weiG.X)
	//yStr, _ := utils.ToBigInt[emulated.Curve25519Fp](&weiG.Y)
	//
	//fmt.Printf("to wei gx: %s\n", xStr.String())
	//fmt.Printf("to wei gy: %s\n", yStr.String())

	//Weix, _ := new(big.Int).SetString("0x726CEB65592B267E90AEBABD3BEF877995C51332DB1C1A3F40F7F594C0914E8C", 0)
	//Weiy, _ := new(big.Int).SetString("0x2FF546E8580D8E3F3F796760E86BAB51C0FA5A7C5E0C9C19A0FCBF6AEE640065", 0)
	//
	//fmt.Printf("wei x: %s\n", Weix.String())
	//fmt.Printf("wei y: %s\n", Weiy.String())

	//denD := emulated2.ValueOf[emulated.Curve25519Fp](-121665)
	//numD := emulated2.ValueOf[emulated.Curve25519Fp](121666)
	//
	//d := field.Div(&denD, &numD)
	//
	//dStr, _ := utils.ToBigInt[emulated.Curve25519Fp](d)
	//fmt.Println(d)
	//fmt.Printf("d: %s\n", dStr.String())
	//
	//dd := emulated2.ValueOf[emulated.Curve25519Fp](D)
	//
	//ddStr, _ := utils.ToBigInt[emulated.Curve25519Fp](&dd)
	//fmt.Printf("dd: %s\n", ddStr.String())

	return nil
}

func TestPreHashEddsa(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness PreHashCircuit[Fp, Fr]

	rx, _ := new(big.Int).SetString("0x74CAF2D2E350E3163A7FCAAED6182D8CC49680EBDCFDFFADC4B2393490FF70C8", 0)
	ry, _ := new(big.Int).SetString("0x32DA53FEFA270C5AD0ABBC1CE6722B20640F6152BDA5A27DCF5812C6871C7789", 0)

	pubx, _ := new(big.Int).SetString("0x00AD32A9840941679E3E18FE874961A46EFAFC457E9117926EEBB5D68493E63C", 0)
	puby, _ := new(big.Int).SetString("0x3DA446D77C2684FFFD12575C411275EDAA4299F4A7282FD124D0DEC379F55218", 0)

	witness.Sig = Signature[Fp, Fr]{
		R: sw_emulated.AffinePoint[Fp]{
			X: emulated.ValueOf[Fp](rx),
			Y: emulated.ValueOf[Fp](ry),
		},
		S: emulated.ValueOf[Fr]("5004556735901913393272427758925840403246877222315506387332009764265656498271"),
	}

	witness.Msg = emulated.Element[Fr]{}

	witness.Hash = emulated.ValueOf[Fr]("1958233733501237659471134851339390337284068724042047466985993338226439154310")

	witness.Pub = PublicKey[Fp, Fr]{
		A: sw_emulated.AffinePoint[Fp]{
			X: emulated.ValueOf[Fp](pubx),
			Y: emulated.ValueOf[Fp](puby),
		},
	}

	assert.CheckCircuit(&circuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.WithValidAssignment(&witness))
}
