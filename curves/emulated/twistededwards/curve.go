package twistededwards

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

func New[Base, Scalars emulated.FieldParams](api frontend.API, params CurveParams) (*Curve[Base, Scalars], error) {
	ba, err := emulated.NewField[Base](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	sa, err := emulated.NewField[Scalars](api)
	if err != nil {
		return nil, fmt.Errorf("new scalar api: %w", err)
	}
	//emuGm := make([]twistededwards.Point[Base], len(params.Gm))
	//for i, v := range params.Gm {
	//	emuGm[i] = AffinePoint[Base]{emulated.ValueOf[Base](v[0]), emulated.ValueOf[Base](v[1])}
	//}
	gx := emulated.ValueOf[Base](params.Gx)
	gy := emulated.ValueOf[Base](params.Gy)

	a := emulated.ValueOf[Base](params.A)
	d := emulated.ValueOf[Base](params.D)

	return &Curve[Base, Scalars]{
		params:    params,
		api:       api,
		baseApi:   ba,
		scalarApi: sa,
		g: &sw_emulated.AffinePoint[Base]{
			X: gx,
			Y: gy,
		},
		a: &a,
		d: &d,
	}, nil
}

type Curve[Base, Scalars emulated.FieldParams] struct {
	// params is the parameters of the curve
	params CurveParams
	// api is the native api, we construct it ourselves to be sure
	api frontend.API
	// baseApi is the api for point operations
	baseApi *emulated.Field[Base]
	// scalarApi is the api for scalar operations
	scalarApi *emulated.Field[Scalars]

	// g is the generator (base point) of the curve.
	g *sw_emulated.AffinePoint[Base]

	//// gm are the pre-computed doubles the generator (base point) of the curve.
	//gm []emulated2.Point[Base]

	a *emulated.Element[Base]
	d *emulated.Element[Base]

	//addA         bool
	//eigenvalue   *emulated.Element[Scalar]
	//thirdRootOne *emulated.Element[Scalar]
}

// Generator returns the base point of the curve. The method does not copy and
// modifying the returned element leads to undefined behaviour!
func (c *Curve[B, S]) Generator() *sw_emulated.AffinePoint[B] {
	return c.g
}

// ToWeierstrassPoint returns twisted Edward curve's point in short Weierstrass form
// X = (5*a + a*y - 5*d*y - d)/(12 - 12*y)
// Y = (a + a*y - d*y -d)/(4*x - 4*x*y))
func (c *Curve[B, S]) ToWeierstrassPoint(point *sw_emulated.AffinePoint[B]) *sw_emulated.AffinePoint[B] {
	field := c.baseApi

	a := c.a
	d := c.d

	four := emulated.ValueOf[B](4)
	five := emulated.ValueOf[B](5)
	twelve := emulated.ValueOf[B](12)

	fiveA := field.Mul(&five, a)
	aY := field.Mul(a, &point.Y)
	dY := field.Mul(d, &point.Y)

	fiveDY := field.Mul(&five, dY)
	twelveY := field.Mul(&twelve, &point.Y)

	numX := field.Sub(field.Add(fiveA, aY), field.Add(fiveDY, d))
	denX := field.Sub(&twelve, twelveY)

	x := field.Div(numX, denX)

	fourX := field.Mul(&four, &point.X)
	fourXY := field.Mul(fourX, &point.Y)

	numY := field.Sub(field.Add(a, aY), field.Add(dY, d))
	denY := field.Sub(fourX, fourXY)

	y := field.Div(numY, denY)

	return &sw_emulated.AffinePoint[B]{X: *x, Y: *y}
}
