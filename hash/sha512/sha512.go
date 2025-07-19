package sha512

import (
	"0x5ea000000/ecip-gnark/permutation/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/bitslice"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

var _seed = uints.NewU64Array([]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
})

type digest struct {
	api  frontend.API
	uapi *uints.BinaryField[uints.U64]
	in   []uints.U8

	minimalLength int
}

func New(api frontend.API, opts ...hash.Option) (hash.BinaryFixedLengthHasher, error) {
	cfg := new(hash.HasherConfig)
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("applying option: %w", err)
		}
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, fmt.Errorf("initializing uints: %w", err)
	}
	return &digest{api: api, uapi: uapi, minimalLength: cfg.MinimalLength}, nil
}

func (d *digest) Write(data []uints.U8) {
	d.in = append(d.in, data...)
}

func (d *digest) padded(bytesLen int) []uints.U8 {
	zeroPadLen := 111 - bytesLen%128
	if zeroPadLen < 0 {
		zeroPadLen += 128
	}
	if cap(d.in) < len(d.in)+9+zeroPadLen {
		d.in = append(d.in, make([]uints.U8, 9+zeroPadLen)...)
		d.in = d.in[:len(d.in)-9-zeroPadLen]
	}
	buf := d.in
	buf = append(buf, uints.NewU8(0x80))
	buf = append(buf, uints.NewU8Array(make([]uint8, zeroPadLen))...)
	lenbuf := make([]uint8, 16)
	binary.BigEndian.PutUint64(lenbuf[8:], uint64(8*bytesLen))
	buf = append(buf, uints.NewU8Array(lenbuf)...)
	return buf
}

func (d *digest) Sum() []uints.U8 {
	var runningDigest [8]uints.U64
	var buf [128]uints.U8
	copy(runningDigest[:], _seed)
	padded := d.padded(len(d.in))
	for i := 0; i < len(padded)/128; i++ {
		copy(buf[:], padded[i*128:(i+1)*128])
		runningDigest = sha512.Permute(d.uapi, runningDigest, buf)
	}
	return d.unpackU8Digest(runningDigest)
}

func (d *digest) unpackU8Digest(digest [8]uints.U64) []uints.U8 {
	var ret []uints.U8
	for i := range digest {
		ret = append(ret, d.uapi.UnpackMSB(digest[i])...)
	}
	return ret
}

func (d *digest) FixedLengthSum(length frontend.Variable) []uints.U8 {
	maxLen := len(d.in)
	comparator := cmp.NewBoundedComparator(d.api, big.NewInt(int64(maxLen+128+16)), false)
	if d.minimalLength > 0 {
		comparator.AssertIsLessEq(d.minimalLength, length)
	}

	data := make([]uints.U8, maxLen)
	copy(data, d.in)
	data = append(data, uints.NewU8Array(make([]uint8, 128+16))...)

	lenMod := d.mod128(length)
	lenModLess112 := comparator.IsLess(lenMod, 112)

	paddingCount := d.api.Sub(128, lenMod)
	paddingCount = d.api.Select(lenModLess112, paddingCount, d.api.Add(paddingCount, 128))
	totalLen := d.api.Add(length, paddingCount)
	last16BytesPos := d.api.Sub(totalLen, 16)

	var dataLenBytes [16]frontend.Variable
	d.bigEndianPutUint128(dataLenBytes[:], d.api.Mul(length, 8))

	for i := d.minimalLength; i <= maxLen; i++ {
		isPaddingStartPos := cmp.IsEqual(d.api, i, length)
		data[i].Val = d.api.Select(isPaddingStartPos, 0x80, data[i].Val)

		isPaddingPos := comparator.IsLess(length, i)
		data[i].Val = d.api.Select(isPaddingPos, 0, data[i].Val)
	}

	for i := d.minimalLength + 1; i < len(data); i++ {
		isLast16BytesPos := cmp.IsEqual(d.api, i, last16BytesPos)
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				data[i+j].Val = d.api.Select(isLast16BytesPos, dataLenBytes[j], data[i+j].Val)
			}
		}
	}

	var runningDigest, resultDigest [8]uints.U64
	var buf [128]uints.U8
	copy(runningDigest[:], _seed)

	for i := 0; i < len(data)/128; i++ {
		copy(buf[:], data[i*128:(i+1)*128])
		runningDigest = sha512.Permute(d.uapi, runningDigest, buf)

		if i < d.minimalLength/128 {
			continue
		} else if i == d.minimalLength/128 {
			copy(resultDigest[:], runningDigest[:])
			continue
		}

		isInRange := comparator.IsLess(i*128, totalLen)
		for j := 0; j < 8; j++ {
			for k := 0; k < 8; k++ {
				resultDigest[j][k].Val = d.api.Select(isInRange, runningDigest[j][k].Val, resultDigest[j][k].Val)
			}
		}
	}
	return d.unpackU8Digest(resultDigest)
}

func (d *digest) Reset() {
	d.in = nil
}

func (d *digest) Size() int { return 64 }

func (d *digest) mod128(v frontend.Variable) frontend.Variable {
	lower, _ := bitslice.Partition(d.api, v, 7, bitslice.WithNbDigits(128))
	return lower
}

func (d *digest) bigEndianPutUint128(b []frontend.Variable, x frontend.Variable) {
	bts := bits.ToBinary(d.api, x, bits.WithNbDigits(128))
	for i := 0; i < 16; i++ {
		b[i] = bits.FromBinary(d.api, bts[(16-i-1)*8:(16-i)*8])
	}
}
