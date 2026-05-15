package verkle

import (
	crand "crypto/rand"
	"fmt"
	mrand "math/rand"
	"reflect"
	"testing"
)

func TestCommitmentCommutativity(t *testing.T) {
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

		// Ordine originale
		treeA := New()
		for i := range keys {
			treeA.Insert(keys[i], vals[i], nil)
		}
		rootA := treeA.Commit()

		// Fisher-Yates shuffle
		perm := mrand.Perm(n)
		treeB := New()
		for _, idx := range perm {
			treeB.Insert(keys[idx], vals[idx], nil)
		}
		rootB := treeB.Commit()

		if !reflect.DeepEqual(rootA, rootB) {
			divergences++
			fmt.Printf("[!] COMMUTATIVITY FAIL iter %d | perm=%v\n", iter, perm)
			fmt.Printf("    rootA=%v\n    rootB=%v\n", rootA, rootB)
			if divergences >= 5 {
				t.Fatalf("too many commutativity failures (%d), aborting", divergences)
			}
		}

		if iter%5000 == 0 {
			fmt.Printf("  iter %5d | divergences so far: %d\n", iter, divergences)
		}
	}

	if divergences > 0 {
		t.Errorf("COMMUTATIVITY BROKEN: %d divergences over 50k iterations", divergences)
	} else {
		fmt.Println("[+] 50k commutativity iterations PASSED")
	}
}
