package eddsa

import (
	"0x5ea000000/ecip-gnark/curves/emulated/twistededwards"
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"math/big"
)

type Signature[Base, Scalar emulated.FieldParams] struct {
	R sw_emulated.AffinePoint[Base]
	S emulated.Element[Scalar]
}

type PublicKey[Base, Scalar emulated.FieldParams] struct {
	A sw_emulated.AffinePoint[Base]
}

func Verify[Base, Scalars emulated.FieldParams](api frontend.API, params twistededwards.CurveParams, sig Signature[Base, Scalars], msg emulated.Element[Scalars], hram emulated.Element[Scalars], pubKey PublicKey[Base, Scalars]) error {
	// 1. prepare
	//edCr, _ := twistededwards.New[Base, Scalars](api, params)
	weiCr, _ := sw_emulated.New[Base, Scalars](api, sw_emulated.GetWei25519Params())
	baseApi, err := emulated.NewField[Base](api)
	if err != nil {
		return err
	}
	// weierstrass neg G
	negGx, _ := new(big.Int).SetString("0x2a78dd0fd02c0339f00b8f02f1c20618a9c13fdf0d617c9aca55c89b025aef35", 0)
	negGy, _ := new(big.Int).SetString("0x5639bb5a38e25dd141b7c45a9c867cdc30902f9e7f8ece9a6487cf0c09d3e2d9", 0)
	negG := sw_emulated.AffinePoint[Base]{
		X: emulated.ValueOf[Base](negGx),
		Y: emulated.ValueOf[Base](negGy),
	}

	// infinity
	zero := baseApi.Zero()
	infinity := sw_emulated.AffinePoint[Base]{X: *zero, Y: *zero}

	fmt.Println(infinity)

	// convert to weierstrass
	//weiR := edCr.ToWeierstrassPoint(&sig.R)
	//weiP := edCr.ToWeierstrassPoint(&pubKey.A)

	// 2. compute hash H(R,A,M)

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
	ps[1] = &pubKey.A

	ss := make([]*emulated.Element[Scalars], 2)
	ss[0] = &sig.S
	ss[1] = &hram

	mul, err := weiCr.MultiScalarMul(ps, ss)
	if err != nil {
		return err
	}
	res := weiCr.AddUnified(mul, &sig.R)

	weiCr.AssertIsEqual(res, &infinity)

	return nil
}
