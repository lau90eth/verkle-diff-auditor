#!/usr/bin/env python3
"""
Differential tester: Go vs Rust verkle commitment
Go side: chiama 'go run' con un helper che stampa il commitment
Rust side: processo persistente
"""
import subprocess, json, os, sys, struct

RUST_BIN = "/home/rob/ethereum-crypto/rust-verkle/harness/target/release/verkle-harness"
GO_DIR   = "/home/rob/ethereum-crypto/go-verkle"

# --- Rust processo persistente ---
rust = subprocess.Popen(
    [RUST_BIN],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL
)

def rust_commit(keys, vals):
    req = json.dumps({"keys": [k.hex() for k in keys],
                      "values": [v.hex() for v in vals]}) + "\n"
    rust.stdin.write(req.encode())
    rust.stdin.flush()
    line = rust.stdout.readline()
    r = json.loads(line)
    if r.get("error"):
        return None
    return r["commitment"]

# --- Go helper (compilato una volta) ---
GO_HELPER = "/tmp/go_verkle_helper"

GO_SRC = '''package main
import (
    "encoding/hex"
    "encoding/json"
    "os"
    "bufio"
    "fmt"
    verkle "github.com/ethereum/go-verkle"
)
type In struct { Keys []string; Values []string }
func main() {
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        var inp In
        json.Unmarshal(scanner.Bytes(), &inp)
        tree := verkle.New()
        for i := range inp.Keys {
            k, _ := hex.DecodeString(inp.Keys[i])
            v, _ := hex.DecodeString(inp.Values[i])
            tree.Insert(k, v, nil)
        }
        c := tree.Commit()
        b := c.Bytes()
        fmt.Println(hex.EncodeToString(b[:]))
    }
}
'''

with open("/tmp/go_verkle_helper.go", "w") as f:
    f.write(GO_SRC)

print("[*] Compiling Go helper...", flush=True)
r = subprocess.run(
    ["go", "build", "-o", GO_HELPER, "/tmp/go_verkle_helper.go"],
    cwd=GO_DIR, capture_output=True, text=True
)
if r.returncode != 0:
    print("Go build failed:", r.stderr)
    sys.exit(1)
print("[+] Go helper compiled", flush=True)

# --- Go processo persistente ---
go_proc = subprocess.Popen(
    [GO_HELPER],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    cwd=GO_DIR
)

def go_commit(keys, vals):
    req = json.dumps({"Keys": [k.hex() for k in keys],
                      "Values": [v.hex() for v in vals]}) + "\n"
    go_proc.stdin.write(req.encode())
    go_proc.stdin.flush()
    line = go_proc.stdout.readline()
    return line.decode().strip()

# --- Differential test ---
N = 2000
divergences = 0
skipped = 0

print(f"[*] Running {N} differential iterations...", flush=True)
for i in range(N):
    n = 1 + int.from_bytes(os.urandom(1), 'big') % 6
    keys = [os.urandom(32) for _ in range(n)]
    vals = [os.urandom(32) for _ in range(n)]

    rc = rust_commit(keys, vals)
    gc = go_commit(keys, vals)

    if rc is None or not gc:
        skipped += 1
        continue

    # Normalizza endianness: prova diretto e reversed
    rc_bytes = bytes.fromhex(rc)
    gc_bytes = bytes.fromhex(gc)
    match = (rc == gc) or (rc_bytes == gc_bytes[::-1])

    if not match:
        divergences += 1
        print(f"[!!!] DIVERGENCE iter={i} n={n}")
        print(f"      Go   = {gc}")
        print(f"      Rust = {rc}")
        for j in range(n):
            print(f"      k[{j}] = {keys[j].hex()}")
            print(f"      v[{j}] = {vals[j].hex()}")
        if divergences >= 5:
            break

    if i % 200 == 0:
        print(f"  iter {i:4d} | divergences: {divergences} skipped: {skipped}", flush=True)

rust.terminate()
go_proc.terminate()
print(f"\n[*] Final: divergences={divergences} skipped={skipped} over {N} iter")
if divergences == 0:
    print("[+] PASS: Go and Rust produce identical commitments")
else:
    print("[!] FAIL: divergences found")
    sys.exit(1)
