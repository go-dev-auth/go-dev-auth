package passkey

// A deliberately small CBOR (RFC 8949) decoder — just enough to read
// WebAuthn attestation objects and COSE keys, which is all this plugin
// ever parses. Depending on a full CBOR library for two well-known
// shapes would be the library's first external dependency, and CBOR
// decoders have a history of being the soft spot in WebAuthn stacks;
// a decoder whose whole surface is visible on one page is easier to
// audit than one imported for generality.
//
// Supported: unsigned/negative integers, byte strings, text strings,
// arrays, maps, booleans, null, and tags (skipped). Indefinite lengths,
// floats and everything else are rejected: authenticators do not emit
// them in the structures we read, so anything using them is malformed
// or malicious input.

import (
	"errors"
	"fmt"
)

var errCBOR = errors.New("passkey: malformed CBOR")

// cborMaxItems bounds collection sizes so a tiny message cannot declare
// a billion-entry map and pin the allocator.
const cborMaxItems = 1 << 16

type cborDecoder struct {
	buf   []byte
	pos   int
	depth int
}

// cborDecode decodes a single CBOR item and requires nothing but
// trailing garbage-free input... trailing bytes are tolerated by
// cborDecodePrefix, used for authData where the COSE key is followed by
// extensions.
func cborDecode(b []byte) (any, error) {
	d := &cborDecoder{buf: b}
	v, err := d.item()
	if err != nil {
		return nil, err
	}
	if d.pos != len(b) {
		return nil, fmt.Errorf("%w: %d trailing bytes", errCBOR, len(b)-d.pos)
	}
	return v, nil
}

// cborDecodePrefix decodes one item from the front of b and returns it
// with the number of bytes it consumed.
func cborDecodePrefix(b []byte) (any, int, error) {
	d := &cborDecoder{buf: b}
	v, err := d.item()
	if err != nil {
		return nil, 0, err
	}
	return v, d.pos, nil
}

func (d *cborDecoder) item() (any, error) {
	if d.depth++; d.depth > 32 {
		return nil, fmt.Errorf("%w: nesting too deep", errCBOR)
	}
	defer func() { d.depth-- }()

	ib, err := d.byte()
	if err != nil {
		return nil, err
	}
	major := ib >> 5
	info := ib & 0x1f

	// Additional info 24..27 carry the argument in the next 1/2/4/8
	// bytes; 28..30 are reserved and 31 (indefinite) is not accepted.
	arg, err := d.argument(info)
	if err != nil {
		return nil, err
	}

	switch major {
	case 0: // unsigned int
		return int64(arg), d.checkInt(arg)
	case 1: // negative int: -1 - arg
		if err := d.checkInt(arg); err != nil {
			return nil, err
		}
		return -1 - int64(arg), nil
	case 2: // byte string
		return d.take(arg)
	case 3: // text string
		b, err := d.take(arg)
		if err != nil {
			return nil, err
		}
		return string(b), nil
	case 4: // array
		if arg > cborMaxItems {
			return nil, fmt.Errorf("%w: array too large", errCBOR)
		}
		out := make([]any, 0, min(int(arg), 64))
		for i := uint64(0); i < arg; i++ {
			v, err := d.item()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5: // map
		if arg > cborMaxItems {
			return nil, fmt.Errorf("%w: map too large", errCBOR)
		}
		out := make(map[any]any, min(int(arg), 64))
		for i := uint64(0); i < arg; i++ {
			k, err := d.item()
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, fmt.Errorf("%w: unsupported map key type %T", errCBOR, k)
			}
			v, err := d.item()
			if err != nil {
				return nil, err
			}
			if _, dup := out[k]; dup {
				// Duplicate keys are how parser differentials start:
				// one consumer sees the first value, another the last.
				return nil, fmt.Errorf("%w: duplicate map key", errCBOR)
			}
			out[k] = v
		}
		return out, nil
	case 6: // tag: skip the tag number, decode the tagged item
		return d.item()
	case 7:
		switch info {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		default:
			return nil, fmt.Errorf("%w: unsupported simple/float value", errCBOR)
		}
	}
	return nil, errCBOR
}

func (d *cborDecoder) byte() (byte, error) {
	if d.pos >= len(d.buf) {
		return 0, fmt.Errorf("%w: truncated", errCBOR)
	}
	b := d.buf[d.pos]
	d.pos++
	return b, nil
}

func (d *cborDecoder) argument(info byte) (uint64, error) {
	switch {
	case info < 24:
		return uint64(info), nil
	case info == 24, info == 25, info == 26, info == 27:
		n := 1 << (info - 24)
		if d.pos+n > len(d.buf) {
			return 0, fmt.Errorf("%w: truncated argument", errCBOR)
		}
		var v uint64
		for i := 0; i < n; i++ {
			v = v<<8 | uint64(d.buf[d.pos+i])
		}
		d.pos += n
		return v, nil
	default:
		return 0, fmt.Errorf("%w: unsupported additional info %d", errCBOR, info)
	}
}

func (d *cborDecoder) take(n uint64) ([]byte, error) {
	if n > uint64(len(d.buf)-d.pos) {
		return nil, fmt.Errorf("%w: truncated string", errCBOR)
	}
	out := make([]byte, n)
	copy(out, d.buf[d.pos:d.pos+int(n)])
	d.pos += int(n)
	return out, nil
}

func (d *cborDecoder) checkInt(arg uint64) error {
	if arg > 1<<62 {
		return fmt.Errorf("%w: integer out of range", errCBOR)
	}
	return nil
}
