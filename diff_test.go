package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// VerkleDifferential runs the same random key-value insertion
// against go-verkle and rust-verkle, then compares the root commitment.
func main() {
	goPath := filepath.Join(os.Getenv("HOME"), "ethereum-crypto", "go-verkle")
	rustPath := filepath.Join(os.Getenv("HOME"), "ethereum-crypto", "rust-verkle")

	// Generate random test vector
	key := make([]byte, 32)
	val := make([]byte, 32)
	rand.Read(key)
	rand.Read(val)

	fmt.Printf("[*] Test vector: key=%x val=%x\n", key, val)

	// Run Go verkle insertion (via go test with custom vector)
	cmdGo := exec.Command("go", "test", "./...", "-run", "TestInsert", "-v")
	cmdGo.Dir = goPath
	cmdGo.Env = append(os.Environ(), fmt.Sprintf("TEST_KEY=%x", key), fmt.Sprintf("TEST_VAL=%x", val))
	outGo, errGo := cmdGo.CombinedOutput()

	// Run Rust verkle insertion
	cmdRust := exec.Command("cargo", "test", "--", "test_insert")
	cmdRust.Dir = rustPath
	cmdRust.Env = append(os.Environ(), fmt.Sprintf("TEST_KEY=%x", key), fmt.Sprintf("TEST_VAL=%x", val))
	outRust, errRust := cmdRust.CombinedOutput()

	fmt.Printf("[Go]    err=%v out=%s\n", errGo, bytes.TrimSpace(outGo))
	fmt.Printf("[Rust]  err=%v out=%s\n", errRust, bytes.TrimSpace(outRust))

	if errGo != nil || errRust != nil {
		fmt.Println("[!] One implementation failed — investigate")
		os.Exit(1)
	}

	// TODO: parse root commitment from output and compare
	fmt.Println("[+] Both implementations completed")
}
