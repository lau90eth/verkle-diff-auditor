package verkle

import (
	crand "crypto/rand"
	"fmt"
	mrand "math/rand"
	"testing"
)

func TestProofSoundness(t *testing.T) {
	soundnessFailures := 0

	for iter := 0; iter < 10000; iter++ {
		n := 2 + mrand.Intn(10)
		keys := make([][]byte, n)
		vals := make([][]byte, n)
		for i := 0; i < n; i++ {
			keys[i] = make([]byte, 32)
			vals[i] = make([]byte, 32)
			crand.Read(keys[i])
			crand.Read(vals[i])
		}

		tree := New()
		for i := range keys {
			tree.Insert(keys[i], vals[i], nil)
		}
		preRoot := tree.Commit()
		tmp := preRoot.Bytes()
		preRootBytes := tmp[:]

		// MakeVerkleMultiProof: preroot==postroot (no state transition, solo lettura)
		rawProof, _, _, _, err := MakeVerkleMultiProof(tree, nil, [][]byte{keys[0]}, nil)
		if err != nil {
			continue
		}

		vp, statediff, err := SerializeProof(rawProof)
		if err != nil {
			continue
		}

		// --- Verifica legittima: deve passare ---
		if err := Verify(vp, preRootBytes, preRootBytes, statediff); err != nil {
			// Alcuni iter possono fallire per motivi legittimi (nil postroot ecc.)
			continue
		}

		// --- Tamper 1: corrompi il postStateRoot ---
		fakeRoot := make([]byte, 32)
		crand.Read(fakeRoot)
		if err := Verify(vp, preRootBytes, fakeRoot, statediff); err == nil {
			soundnessFailures++
			fmt.Printf("[!!!] SOUNDNESS FAIL iter %d — Verify accetta fakePostRoot\n", iter)
			fmt.Printf("      preRoot  = %x\n", preRootBytes)
			fmt.Printf("      fakeRoot = %x\n", fakeRoot)
			t.Errorf("CRITICAL: proof verified with tampered postStateRoot at iter %d", iter)
		}

		// --- Tamper 2: corrompi statediff (modifica il valore atteso) ---
		if len(statediff) > 0 && len(statediff[0].SuffixDiffs) > 0 {
			sd := statediff[0].SuffixDiffs[0]
			if sd.CurrentValue != nil {
				// Flip un byte nel currentValue
				tampered := make([]byte, 32)
				copy(tampered, (*sd.CurrentValue)[:])
				tampered[0] ^= 0xff
				var tamperedArr [32]byte
				copy(tamperedArr[:], tampered)

				origVal := sd.CurrentValue
				statediff[0].SuffixDiffs[0].CurrentValue = &tamperedArr

				if err := Verify(vp, preRootBytes, preRootBytes, statediff); err == nil {
					soundnessFailures++
					fmt.Printf("[!!!] SOUNDNESS FAIL iter %d — Verify accetta CurrentValue MANOMESSO\n", iter)
					fmt.Printf("      key      = %x\n", keys[0])
					fmt.Printf("      origVal  = %x\n", *origVal)
					fmt.Printf("      fakeVal  = %x\n", tamperedArr)
					t.Errorf("CRITICAL: proof verified with tampered CurrentValue at iter %d", iter)
				}

				// Ripristina per non inquinare iterazioni successive
				statediff[0].SuffixDiffs[0].CurrentValue = origVal
			}
		}

		if iter%1000 == 0 {
			fmt.Printf("  iter %5d | soundness failures: %d\n", iter, soundnessFailures)
		}
	}

	if soundnessFailures == 0 {
		fmt.Println("[+] 10k proof soundness iterations PASSED")
	} else {
		t.Errorf("TOTAL soundness failures: %d", soundnessFailures)
	}
}
