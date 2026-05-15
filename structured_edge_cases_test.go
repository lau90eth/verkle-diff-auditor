package verkle

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	mrand "math/rand"
	"reflect"
	"testing"
)

// BLS12-381 scalar field order
var blsOrder, _ = new(big.Int).SetString(
	"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16,
)

// --- Helper ---

func newKey(stem []byte, suffix byte) []byte {
	k := make([]byte, 32)
	copy(k[:31], stem)
	k[31] = suffix
	return k
}

func randStem() []byte {
	s := make([]byte, 31)
	crand.Read(s)
	return s
}

func commitBytes(tree VerkleNode) []byte {
	c := tree.Commit()
	b := c.Bytes()
	return b[:]
}

// =============================================================
// TEST 1: Stem Collision
// Due chiavi con stessa stem, suffix diversi.
// Forza LeafNode con due suffix attivi.
// =============================================================
func TestStemCollision(t *testing.T) {
	failures := 0
	for iter := 0; iter < 20000; iter++ {
		stem := randStem()
		nSuffixes := 2 + mrand.Intn(10)
		keys := make([][]byte, nSuffixes)
		vals := make([][]byte, nSuffixes)

		// Suffix unici
		suffixes := mrand.Perm(256)[:nSuffixes]
		for i, s := range suffixes {
			keys[i] = newKey(stem, byte(s))
			vals[i] = make([]byte, 32)
			crand.Read(vals[i])
		}

		// Insert ordine forward
		treeA := New()
		for i := range keys {
			treeA.Insert(keys[i], vals[i], nil)
		}
		rootA := commitBytes(treeA)

		// Insert ordine reverse
		treeB := New()
		for i := len(keys) - 1; i >= 0; i-- {
			treeB.Insert(keys[i], vals[i], nil)
		}
		rootB := commitBytes(treeB)

		if !reflect.DeepEqual(rootA, rootB) {
			failures++
			fmt.Printf("[!!!] STEM COLLISION FAIL iter %d stem=%x suffixes=%v\n",
				iter, stem, suffixes)
			if failures >= 3 {
				t.Fatalf("too many stem collision failures")
			}
		}

		// Proof su tutte le chiavi dello stem
		rawProof, _, _, _, err := MakeVerkleMultiProof(treeA, nil, keys, nil)
		if err != nil {
			continue
		}
		vp, sd, err := SerializeProof(rawProof)
		if err != nil {
			continue
		}
		if err := Verify(vp, rootA, rootA, sd); err != nil {
			failures++
			fmt.Printf("[!!!] STEM MULTIPROOF FAIL iter %d: %v\n", iter, err)
		}

		if iter%5000 == 0 {
			fmt.Printf("  [stem] iter %5d | failures: %d\n", iter, failures)
		}
	}
	if failures == 0 {
		fmt.Println("[+] TestStemCollision PASSED")
	} else {
		t.Errorf("stem collision failures: %d", failures)
	}
}

// =============================================================
// TEST 2: Field Boundary Values
// Valori vicini all'ordine del campo BLS12-381.
// Testa riduzione modulare inconsistente tra path.
// =============================================================
func TestFieldBoundaryValues(t *testing.T) {
	failures := 0

	// Candidati boundary
	boundaries := func() [][]byte {
		order := new(big.Int).Set(blsOrder)
		candidates := []*big.Int{
			new(big.Int).Sub(order, big.NewInt(1)), // p-1
			new(big.Int).Set(order),                // p   (deve ridursi a 0)
			new(big.Int).Add(order, big.NewInt(1)), // p+1 (deve ridursi a 1)
			new(big.Int).Lsh(big.NewInt(1), 255),   // 2^255
			new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)), // 2^256-1
			big.NewInt(0),
			big.NewInt(1),
		}
		out := make([][]byte, len(candidates))
		for i, c := range candidates {
			b := c.Bytes()
			v := make([]byte, 32)
			copy(v[32-len(b):], b)
			out[i] = v
		}
		return out
	}()

	for _, val := range boundaries {
		stem := randStem()
		key := newKey(stem, 0x00)

		// treeA: insert diretto con boundary value
		treeA := New()
		treeA.Insert(key, val, nil)
		rootA := commitBytes(treeA)

		// treeB: stesso insert (determinismo)
		treeB := New()
		treeB.Insert(key, val, nil)
		rootB := commitBytes(treeB)

		if !reflect.DeepEqual(rootA, rootB) {
			failures++
			fmt.Printf("[!!!] FIELD BOUNDARY non-deterministic val=%x\n", val)
			t.Errorf("non-deterministic commitment for boundary value %x", val)
		}

		// Proof soundness sul boundary value
		rawProof, _, _, _, err := MakeVerkleMultiProof(treeA, nil, [][]byte{key}, nil)
		if err != nil {
			continue
		}
		vp, sd, err := SerializeProof(rawProof)
		if err != nil {
			continue
		}
		if err := Verify(vp, rootA, rootA, sd); err != nil {
			failures++
			fmt.Printf("[!!!] FIELD BOUNDARY proof fail val=%x err=%v\n", val, err)
			t.Errorf("proof failed for boundary value %x: %v", val, err)
		}

		// Tamper: valore adiacente (val+1 mod 2^256) non deve verificare
		fakeVal := make([]byte, 32)
		copy(fakeVal, val)
		for i := 31; i >= 0; i-- {
			fakeVal[i]++
			if fakeVal[i] != 0 {
				break
			}
		}
		if reflect.DeepEqual(fakeVal, val) {
			continue
		}

		// Modifica statediff con fakeVal
		if len(sd) > 0 && len(sd[0].SuffixDiffs) > 0 && sd[0].SuffixDiffs[0].CurrentValue != nil {
			var arr [32]byte
			copy(arr[:], fakeVal)
			orig := sd[0].SuffixDiffs[0].CurrentValue
			sd[0].SuffixDiffs[0].CurrentValue = &arr
			if err := Verify(vp, rootA, rootA, sd); err == nil {
				failures++
				fmt.Printf("[!!!] FIELD BOUNDARY soundness FAIL — accepted val+1 for boundary val=%x\n", val)
				t.Errorf("CRITICAL: soundness failure on boundary value %x", val)
			}
			sd[0].SuffixDiffs[0].CurrentValue = orig
		}
	}

	fmt.Printf("[+] TestFieldBoundaryValues done | failures: %d\n", failures)
}

// =============================================================
// TEST 3: Update Idempotency
// Insert k→v1 poi update k→v2 deve dare stesso root
// di un albero con solo k→v2 inserito direttamente.
// =============================================================
func TestUpdateIdempotency(t *testing.T) {
	failures := 0
	for iter := 0; iter < 30000; iter++ {
		stem := randStem()
		suffix := byte(mrand.Intn(256))
		key := newKey(stem, suffix)

		v1 := make([]byte, 32)
		v2 := make([]byte, 32)
		crand.Read(v1)
		crand.Read(v2)
		// Assicura v1 != v2
		for reflect.DeepEqual(v1, v2) {
			crand.Read(v2)
		}

		// treeA: insert v1, poi overwrite con v2
		treeA := New()
		treeA.Insert(key, v1, nil)
		treeA.Insert(key, v2, nil)
		rootA := commitBytes(treeA)

		// treeB: insert diretto v2
		treeB := New()
		treeB.Insert(key, v2, nil)
		rootB := commitBytes(treeB)

		if !reflect.DeepEqual(rootA, rootB) {
			failures++
			fmt.Printf("[!!!] UPDATE IDEMPOTENCY FAIL iter %d\n", iter)
			fmt.Printf("      key  = %x\n", key)
			fmt.Printf("      v1   = %x\n", v1)
			fmt.Printf("      v2   = %x\n", v2)
			fmt.Printf("      rootA= %x\n", rootA)
			fmt.Printf("      rootB= %x\n", rootB)
			if failures >= 3 {
				t.Fatalf("too many idempotency failures")
			}
		}

		if iter%5000 == 0 {
			fmt.Printf("  [update] iter %5d | failures: %d\n", iter, failures)
		}
	}
	if failures == 0 {
		fmt.Println("[+] TestUpdateIdempotency PASSED")
	} else {
		t.Errorf("update idempotency failures: %d", failures)
	}
}
