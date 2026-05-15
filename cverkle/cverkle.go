package cverkle

/*
#cgo LDFLAGS: -L${SRCDIR} -lc_verkle -Wl,-rpath,${SRCDIR}
#include "c_verkle.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/hex"
	"fmt"
	"unsafe"
)

type Context struct {
	ptr *C.Context
}

func NewContext() *Context {
	return &Context{ptr: C.context_new()}
}

func (c *Context) Free() {
	C.context_free(c.ptr)
}

// MultiScalarMul: scalars è una slice di 32-byte scalars concatenati
// Ritorna il commitment come 32 bytes
func (c *Context) MultiScalarMul(scalars []byte) ([]byte, error) {
	if len(scalars)%32 != 0 {
		return nil, fmt.Errorf("scalars must be multiple of 32 bytes, got %d", len(scalars))
	}
	out := make([]byte, 64) // uncompressed point
	C.multi_scalar_mul(
		c.ptr,
		(*C.uint8_t)(unsafe.Pointer(&scalars[0])),
		C.uintptr_t(len(scalars)),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	return out, nil
}

// CommitmentHex: wrapper conveniente per confronto con go-verkle
func (c *Context) CommitmentHex(scalars []byte) (string, error) {
	out, err := c.MultiScalarMul(scalars)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(out), nil
}
