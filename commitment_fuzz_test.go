package verkle

import (
	crand "crypto/rand"
	"fmt"
	mrand "math/rand"
	"reflect"
	"testing"
)

func TestCommitmentConsistency(t *testing.T) {
	divergences := 0
	for iter := 0; iter < 50000; iter++ {
		n := 2 + mrand.Intn(20)
		keys := make([][]byte, n)
		vals := make([][]byte, n)
		for i := 0; i < n; i++ {
			keys[i] = make([]byte, 32)
			vals[i] = make([]byte, 32)
			crand.Read(keys[i])
			crand.Read(vals[i])
		}

		// Test 1: same data, same order = same commitment
		treeA := New()
		treeB := New()
		for i := range keys {
			treeA.Insert(keys[i], vals[i], nil)
			treeB.Insert(keys[i], vals[i], nil)
		}
		rootA := treeA.Commit()
		rootB := treeB.Commit()
		if !reflect.DeepEqual(rootA, rootB) {
			divergences++
			fmt.Printf("[!] COMMITMENT MISMATCH iter %d | A=%v B=%v\n", iter, rootA, rootB)
		}

		// Test 2: same data, shuffled order = same commitment
		keysC := make([][]byte, n)
		valsC := make([][]byte, n)
		copy(keysC, keys)
		copy(valsC, vals)
		for i := len(keysC) - 1; i > 0; i-- {
			j := mrand.Intn(i + 1)
			keysC[i], keysC[j] = keysC[j], keysC[i]
			valsC[i], valsC[j] = valsC[j], valsC[i]
		}
		treeC := New()
		for i := range keysC {
			treeC.Insert(keysC[i], valsC[i], nil)
		}
		rootC := treeC.Commit()
		if !reflect.DeepEqual(rootA, rootC) {
			divergences++
			fmt.Printf("[!] ORDER COMMITMENT MISMATCH iter %d | A=%v C=%v\n", iter, rootA, rootC)
		}

		if iter%5000 == 0 && divergences == 0 {
			fmt.Printf("  iter %5d | OK\n", iter)
		}
	}
	if divergences > 0 {
		t.Fatalf("Total commitment divergences: %d", divergences)
	}
}
