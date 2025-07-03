package shortweierstrasses

import (
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"math/big"
)

// GetWei25519Params returns curve parameters for the curve Wei25519 (Weierstrass curve birational equivalent with
// Ed25519). When initialising new curve, use the base field [emulated.Curve25519Fp] and scalar
// field [emulated.Curve25519Fr].
func GetWei25519Params() sw_emulated.CurveParams {
	//_, g1aff := secp256k1.Generators()

	a, _ := new(big.Int).SetString("19298681539552699237261830834781317975544997444273427339909597334573241639236", 10)
	b, _ := new(big.Int).SetString("5575174666981890890764528907825714081824110372790101231529440083956729358436", 10)
	gx, _ := new(big.Int).SetString("19298681539552699237261830834781317975544997444273427339909597334652188435546", 10)
	gy, _ := new(big.Int).SetString("14781619447589544791020593568409986887264606134616475288964881837755586237401", 10)

	//lambda, _ := new(big.Int).SetString("37718080363155996902926221483475020450927657555482586988616620542887997980018", 10)
	//omega, _ := new(big.Int).SetString("55594575648329892869085402983802832744385952214688224221778511981742606582254", 10)
	return sw_emulated.CurveParams{
		A:  a,
		B:  b,
		Gx: gx,
		Gy: gy,
		//Gm:           computeSecp256k1Table(),
		//Eigenvalue:   lambda,
		//ThirdRootOne: omega,
	}
}
