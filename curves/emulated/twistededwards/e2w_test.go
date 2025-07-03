package twistededwards

import (
	"0x5ea000000/ecip-gnark/math/emulated"
	"0x5ea000000/ecip-gnark/utils"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	emulated2 "github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

type E2WCircuit[Fp, Fr emulated2.FieldParams] struct {
	EPoint, WPoint sw_emulated.AffinePoint[Fp]
}

func (c *E2WCircuit[Fp, Fr]) Define(api frontend.API) error {
	A, _ := new(big.Int).SetString("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffec", 0)
	D, _ := new(big.Int).SetString("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3", 0)
	Gx, _ := new(big.Int).SetString("0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", 0)
	Gy, _ := new(big.Int).SetString("0x6666666666666666666666666666666666666666666666666666666666666658", 0)

	params := CurveParams{
		A:  A,
		D:  D,
		Gx: Gx,
		Gy: Gy,
	}
	cr, _ := New[Fp, Fr](api, params)

	baseApi, _ := emulated2.NewField[Fp](api)

	wei := cr.ToWeierstrassPoint(&c.EPoint)

	str, _ := utils.ToBigInt[Fp](&wei.X)
	fmt.Printf("to wei x: %s\n", str.String())

	str, _ = utils.ToBigInt[Fp](&wei.Y)
	fmt.Printf("to wei y: %s\n", str.String())

	str, _ = utils.ToBigInt[Fp](&c.WPoint.X)
	fmt.Printf("origin wei x: %s\n", str.String())

	str, _ = utils.ToBigInt[Fp](&c.WPoint.Y)
	fmt.Printf("origin wei y: %s\n", str.String())

	baseApi.AssertIsEqual(&c.WPoint.X, &wei.X)
	baseApi.AssertIsEqual(&c.WPoint.Y, &wei.Y)

	//weix := baseApi.Reduce(&wei.X)
	//weixBits := baseApi.ToBits(weix)
	//wx := baseApi.Reduce(&c.WPoint.X)
	//wxBits := baseApi.ToBits(wx)
	//if len(weixBits) != len(wxBits) {
	//	panic("non-equal lengths")
	//}
	//for i := range wxBits {
	//	api.AssertIsEqual(wxBits[i], weixBits[i])
	//}
	//
	//weiy := baseApi.Reduce(&wei.Y)
	//weiyBits := baseApi.ToBits(weiy)
	//wy := baseApi.Reduce(&c.WPoint.Y)
	//wyBits := baseApi.ToBits(wy)
	//if len(weiyBits) != len(wyBits) {
	//	panic("non-equal lengths")
	//}
	//for i := range wyBits {
	//	api.AssertIsEqual(wyBits[i], weiyBits[i])
	//}

	return nil
}

func TestE2WSuccess(t *testing.T) {
	assert := test.NewAssert(t)
	std.RegisterHints()

	var circuit, witness E2WCircuit[emulated.Curve25519Fp, emulated.Curve25519Fr]

	witness.EPoint = sw_emulated.AffinePoint[emulated.Curve25519Fp]{
		X: emulated2.ValueOf[emulated.Curve25519Fp]("15112221349535400772501151409588531511454012693041857206046113283949847762202"),
		Y: emulated2.ValueOf[emulated.Curve25519Fp]("46316835694926478169428394003475163141307993866256225615783033603165251855960"),
	}

	witness.WPoint = sw_emulated.AffinePoint[emulated.Curve25519Fp]{
		X: emulated2.ValueOf[emulated.Curve25519Fp]("19210687000535497554771480197334579066178916638360430415404683479331899109173"),
		Y: emulated2.ValueOf[emulated.Curve25519Fp]("18895136298852160426215908827706757709362468741134365248309716069351496097044"),
	}

	assert.CheckCircuit(&circuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.WithValidAssignment(&witness))
}

func TestE2WFail(t *testing.T) {
	assert := test.NewAssert(t)
	std.RegisterHints()

	var circuit, witness E2WCircuit[emulated.Curve25519Fp, emulated.Curve25519Fr]

	witness.EPoint = sw_emulated.AffinePoint[emulated.Curve25519Fp]{
		X: emulated2.ValueOf[emulated.Curve25519Fp]("15112221349535400772501151409588531511454012693041857206046113283949847762202"),
		Y: emulated2.ValueOf[emulated.Curve25519Fp]("463168356949264781694283940034751631413079938662562256157830336031652518559601"),
	}

	witness.WPoint = sw_emulated.AffinePoint[emulated.Curve25519Fp]{
		X: emulated2.ValueOf[emulated.Curve25519Fp]("19210687000535497554771480197334579066178916638360430415404683479331899109173"),
		Y: emulated2.ValueOf[emulated.Curve25519Fp]("18895136298852160426215908827706757709362468741134365248309716069351496097044"),
	}

	assert.CheckCircuit(&circuit, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16), test.WithInvalidAssignment(&witness))
}
