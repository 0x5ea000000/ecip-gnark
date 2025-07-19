package sha512

import "github.com/consensys/gnark/std/math/uints"

var _K = uints.NewU64Array([]uint64{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
})

func Permute(uapi *uints.BinaryField[uints.U64], currentHash [8]uints.U64, p [128]uints.U8) (newHash [8]uints.U64) {
	var w [80]uints.U64

	// W[0..15]
	for i := 0; i < 16; i++ {
		w[i] = uapi.PackMSB(
			p[8*i+0], p[8*i+1], p[8*i+2], p[8*i+3],
			p[8*i+4], p[8*i+5], p[8*i+6], p[8*i+7],
		)
	}

	// W[16..79]
	for i := 16; i < 80; i++ {
		v1 := w[i-2]
		t1 := uapi.Xor(
			uapi.Lrot(v1, -19),
			uapi.Lrot(v1, -61),
			uapi.Rshift(v1, 6),
		)
		v2 := w[i-15]
		t2 := uapi.Xor(
			uapi.Lrot(v2, -1),
			uapi.Lrot(v2, -8),
			uapi.Rshift(v2, 7),
		)
		w[i] = uapi.Add(t1, w[i-7], t2, w[i-16])
	}

	// Initialize working variables
	a, b, c, d := currentHash[0], currentHash[1], currentHash[2], currentHash[3]
	e, f, g, h := currentHash[4], currentHash[5], currentHash[6], currentHash[7]

	for i := 0; i < 80; i++ {
		S1 := uapi.Xor(
			uapi.Lrot(e, -14),
			uapi.Lrot(e, -18),
			uapi.Lrot(e, -41),
		)
		ch := uapi.Xor(
			uapi.And(e, f),
			uapi.And(uapi.Not(e), g),
		)
		t1 := uapi.Add(h, S1, ch, _K[i], w[i])

		S0 := uapi.Xor(
			uapi.Lrot(a, -28),
			uapi.Lrot(a, -34),
			uapi.Lrot(a, -39),
		)
		maj := uapi.Xor(
			uapi.And(a, b),
			uapi.And(a, c),
			uapi.And(b, c),
		)
		t2 := uapi.Add(S0, maj)

		h = g
		g = f
		f = e
		e = uapi.Add(d, t1)
		d = c
		c = b
		b = a
		a = uapi.Add(t1, t2)
	}

	// Compute new hash state
	currentHash[0] = uapi.Add(currentHash[0], a)
	currentHash[1] = uapi.Add(currentHash[1], b)
	currentHash[2] = uapi.Add(currentHash[2], c)
	currentHash[3] = uapi.Add(currentHash[3], d)
	currentHash[4] = uapi.Add(currentHash[4], e)
	currentHash[5] = uapi.Add(currentHash[5], f)
	currentHash[6] = uapi.Add(currentHash[6], g)
	currentHash[7] = uapi.Add(currentHash[7], h)

	return currentHash
}
