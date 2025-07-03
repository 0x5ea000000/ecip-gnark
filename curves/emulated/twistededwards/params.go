package twistededwards

import "math/big"

// CurveParams defines parameters of an elliptic curve in twisted Edward form
// given by the equation
//
//	ax² + y² = 1 + dx²y²
//
// The base point is defined by (Gx, Gy).
type CurveParams struct {
	A  *big.Int // a in curve equation
	D  *big.Int // d in curve equation
	Gx *big.Int // base point x
	Gy *big.Int // base point y

	//Gm [][2]*big.Int // m*base point coords
	//Eigenvalue   *big.Int      // endomorphism eigenvalue
	//ThirdRootOne *big.Int      // endomorphism image scaler
}
