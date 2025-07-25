package eddsa

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/emulated"
)

type Signature[Base, Scalar emulated.FieldParams] struct {
	R sw_emulated.AffinePoint[Base]
	S emulated.Element[Scalar]
}

type PublicKey[Base, Scalar emulated.FieldParams] struct {
	A sw_emulated.AffinePoint[Base]
}

type Config struct {
	Hasher  hash.BinaryHasher
	FromWei bool
}

func Verify[Base, Scalars emulated.FieldParams](api frontend.API, sig Signature[Base, Scalars], msg emulated.Element[Scalars], hram emulated.Element[Scalars], pubKey PublicKey[Base, Scalars], config Config) error {
	// 1. prepare
	weiCr, _ := sw_emulated.New[Base, Scalars](api, sw_emulated.GetWei25519Params())
	baseApi, err := emulated.NewField[Base](api)
	if err != nil {
		return err
	}
	// wei25519 neg G
	negG := sw_emulated.AffinePoint[Base]{
		X: *baseApi.NewElement("0x2a78dd0fd02c0339f00b8f02f1c20618a9c13fdf0d617c9aca55c89b025aef35"),
		Y: *baseApi.NewElement("0x5639bb5a38e25dd141b7c45a9c867cdc30902f9e7f8ece9a6487cf0c09d3e2d9"),
	}

	// infinity
	//zero := baseApi.Zero()
	//infinity := sw_emulated.AffinePoint[Base]{X: *zero, Y: *zero}
	var R, A *sw_emulated.AffinePoint[Base]

	// convert to weierstrass
	if !config.FromWei {
		R = weiCr.FromEdwardsPoint(&sig.R, baseApi.NewElement("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec"), baseApi.NewElement("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"))
		A = weiCr.FromEdwardsPoint(&pubKey.A, baseApi.NewElement("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec"), baseApi.NewElement("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"))
	} else {
		R = &sig.R
		A = &pubKey.A
	}

	// 2. compute hash H(R,A,M)
	//hasher, err := sha512.New(api)
	//fmt.Println(reflect.TypeOf(sig.R.Y.Limbs[0]))
	//
	//b := sig.R.Y.Limbs[0].(big.Int)
	//hasher.Write(b.Bytes())
	//hash.Write(sig.R.X.Limbs)
	//hash.Write(sig.R.Y.Limbs)
	//hash.Write(pubKey.A.X.Limbs)
	//hash.Write(pubKey.A.Y.Limbs)
	//hash.Write(msg.Limbs)

	//hRAM := hash.Sum()
	//
	//Gx := emulated.ValueOf[Base](params.Gx)
	//Gy := emulated.ValueOf[Base](params.Gy)
	//
	//base := emulated2.Point[Base]{
	//	X: Gx,
	//	Y: Gy,
	//}

	// 3. [S]*-G + [H(R,A,M)]*A + R == 0
	ps := make([]*sw_emulated.AffinePoint[Base], 2)
	ps[0] = &negG
	ps[1] = A

	ss := make([]*emulated.Element[Scalars], 2)
	ss[0] = &sig.S
	ss[1] = &hram

	mul, err := weiCr.MultiScalarMul(ps, ss)
	if err != nil {
		return err
	}
	res := weiCr.Neg(R)
	weiCr.AssertIsEqual(mul, res)

	//res := weiCr.AddUnified(mul, &sig.R)
	//weiCr.AssertIsEqual(res, &infinity)

	return nil
}
