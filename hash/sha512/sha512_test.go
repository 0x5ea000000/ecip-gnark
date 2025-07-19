package sha512

import (
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type sha512Circuit struct {
	In       []uints.U8
	Expected [64]uints.U8
}

func (c *sha512Circuit) Define(api frontend.API) error {
	h, err := New(api)
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}
	h.Write(c.In)
	res := h.Sum()
	if len(res) != 64 {
		return fmt.Errorf("not 64 bytes")
	}
	for i := range c.Expected {
		uapi.ByteAssertEq(c.Expected[i], res[i])
	}
	return nil
}

func TestSHA512(t *testing.T) {
	bts := make([]byte, 310)
	_, _ = rand.Read(bts)
	dgst := sha512.Sum512(bts)
	witness := sha512Circuit{
		In: uints.NewU8Array(bts),
	}
	copy(witness.Expected[:], uints.NewU8Array(dgst[:]))
	err := test.IsSolved(&sha512Circuit{In: make([]uints.U8, len(bts))}, &witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
}

type sha512FixedLengthCircuit struct {
	In       []uints.U8
	Length   frontend.Variable
	Expected [64]uints.U8

	minimalLength int
}

func (c *sha512FixedLengthCircuit) Define(api frontend.API) error {
	h, err := New(api, hash.WithMinimalLength(c.minimalLength))
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}
	h.Write(c.In)
	res := h.FixedLengthSum(c.Length)
	if len(res) != 64 {
		return fmt.Errorf("not 64 bytes")
	}
	for i := range c.Expected {
		uapi.ByteAssertEq(c.Expected[i], res[i])
	}
	return nil
}

func TestSHA512FixedLengthSum(t *testing.T) {
	const maxLen = 160
	assert := test.NewAssert(t)
	bts := make([]byte, maxLen)
	_, err := rand.Read(bts)
	assert.NoError(err)

	for _, lengthBound := range []int{0, 1, 127, 128, 129, len(bts)} {
		circuit := &sha512FixedLengthCircuit{In: make([]uints.U8, len(bts)), minimalLength: lengthBound}
		for _, length := range []int{0, 1, 127, 128, 129, len(bts)} {
			assert.Run(func(assert *test.Assert) {
				dgst := sha512.Sum512(bts[:length])
				witness := &sha512FixedLengthCircuit{
					In:       uints.NewU8Array(bts),
					Length:   length,
					Expected: [64]uints.U8(uints.NewU8Array(dgst[:])),
				}

				err = test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
				if length >= lengthBound {
					assert.NoError(err)
				} else {
					assert.Error(err, "expected error for length < lengthBound")
				}
			}, fmt.Sprintf("bound=%d/length=%d", lengthBound, length))
		}
	}
}
