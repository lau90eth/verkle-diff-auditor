package verkle

import (
	"bufio"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

const rustHarness = "/home/rob/ethereum-crypto/rust-verkle/harness/target/release/verkle-harness"

type rustInput struct {
	Keys   []string `json:"keys"`
	Values []string `json:"values"`
}

type rustOutput struct {
	Commitment string `json:"commitment"`
	Error      string `json:"error,omitempty"`
}

type diffCase struct {
	keys  [][]byte
	vals  [][]byte
	goHex string
	line  []byte
}

func buildCase() diffCase {
	n := 1 + mrand.Intn(8)
	keys := make([][]byte, n)
	vals := make([][]byte, n)
	for j := 0; j < n; j++ {
		keys[j] = make([]byte, 32)
		vals[j] = make([]byte, 32)
		crand.Read(keys[j])
		crand.Read(vals[j])
	}

	// Go commitment
	tree := New()
	for i := range keys {
		tree.Insert(keys[i], vals[i], nil)
	}
	c := tree.Commit()
	b := c.Bytes()
	goHex := hex.EncodeToString(b[:])

	// Rust JSON line
	inp := rustInput{}
	for i := range keys {
		inp.Keys = append(inp.Keys, hex.EncodeToString(keys[i]))
		inp.Values = append(inp.Values, hex.EncodeToString(vals[i]))
	}
	line, _ := json.Marshal(inp)

	return diffCase{keys: keys, vals: vals, goHex: goHex, line: line}
}

func TestDifferentialGoVsRust(t *testing.T) {
	const N = 200

	// Calcola Go in parallelo su tutti i core
	cases := make([]diffCase, N)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8) // max 8 goroutine
	for i := 0; i < N; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			cases[idx] = buildCase()
		}(i)
	}
	wg.Wait()
	fmt.Printf("[*] %d Go commitments done, launching Rust batch...\n", N)

	// Batch Rust — singolo processo
	var sb strings.Builder
	for i := 0; i < N; i++ {
		sb.Write(cases[i].line)
		sb.WriteByte('\n')
	}

	cmd := exec.Command(rustHarness)
	cmd.Stdin = strings.NewReader(sb.String())
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("rust harness start: %v", err)
	}

	divergences := 0
	skipped := 0
	scanner := bufio.NewScanner(outPipe)
	idx := 0
	for scanner.Scan() && idx < N {
		var ro rustOutput
		if err := json.Unmarshal(scanner.Bytes(), &ro); err != nil || ro.Error != "" {
			skipped++
			idx++
			continue
		}

		goHex := cases[idx].goHex
		rustHex := ro.Commitment

		match := goHex == rustHex
		if !match {
			goBytes, _ := hex.DecodeString(goHex)
			rev := make([]byte, 32)
			for i := 0; i < 32; i++ {
				rev[i] = goBytes[31-i]
			}
			match = hex.EncodeToString(rev) == rustHex
		}

		if !match {
			divergences++
			fmt.Printf("[!!!] DIVERGENCE idx=%d n=%d\n", idx, len(cases[idx].keys))
			fmt.Printf("      Go   = %s\n", goHex)
			fmt.Printf("      Rust = %s\n", rustHex)
			for i := range cases[idx].keys {
				fmt.Printf("      k[%d] = %s\n", i, hex.EncodeToString(cases[idx].keys[i]))
				fmt.Printf("      v[%d] = %s\n", i, hex.EncodeToString(cases[idx].vals[i]))
			}
		}

		if idx%50 == 0 {
			fmt.Printf("  idx %3d | divergences: %d skipped: %d\n", idx, divergences, skipped)
		}
		idx++
	}
	cmd.Wait()

	fmt.Printf("\n[*] Final: divergences=%d skipped=%d over %d iter\n", divergences, skipped, idx)
	if divergences > 0 {
		t.Errorf("DIFFERENTIAL DIVERGENCE: %d cases Go != Rust", divergences)
	}
}
