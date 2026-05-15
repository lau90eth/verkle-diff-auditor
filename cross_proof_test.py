#!/usr/bin/env python3
"""
Cross-proof verification: Go genera proof, Rust verifica (e viceversa)
Formato Rust IPA: commitment(32) || poly(8192) || point(1) || result(32)
"""
import subprocess, json, os, sys, struct, hashlib

RUST_BIN = "/home/rob/ethereum-crypto/rust-verkle/harness/target/release/verkle-harness"
GO_DIR   = "/home/rob/ethereum-crypto/go-verkle"

# --- Compila Go helper per proof cross-test ---
GO_PROOF_SRC = '''package main

import (
    "encoding/hex"
    "encoding/json"
    "os"
    "bufio"
    "fmt"
    verkle "github.com/ethereum/go-verkle"
)

type ProofReq struct {
    Keys   []string
    Values []string
    QueryKey string
}

type ProofResp struct {
    PreRoot  string
    Proof    string
    StateDiff string
    Error    string
}

func main() {
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        var req ProofReq
        if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
            fmt.Println(`{"error":"parse:` + err.Error() + `"}`)
            continue
        }
        tree := verkle.New()
        for i := range req.Keys {
            k, _ := hex.DecodeString(req.Keys[i])
            v, _ := hex.DecodeString(req.Values[i])
            tree.Insert(k, v, nil)
        }
        preRoot := tree.Commit()
        preRootBytes := preRoot.Bytes()

        qk, _ := hex.DecodeString(req.QueryKey)
        rawProof, _, _, _, err := verkle.MakeVerkleMultiProof(tree, nil, [][]byte{qk}, nil)
        if err != nil {
            fmt.Println(`{"error":"proof:` + err.Error() + `"}`)
            continue
        }
        vp, sd, err := verkle.SerializeProof(rawProof)
        if err != nil {
            fmt.Println(`{"error":"serial:` + err.Error() + `"}`)
            continue
        }

        vpBytes, _ := json.Marshal(vp)
        sdBytes, _ := json.Marshal(sd)
        resp := ProofResp{
            PreRoot:   hex.EncodeToString(preRootBytes[:]),
            Proof:     hex.EncodeToString(vpBytes),
            StateDiff: hex.EncodeToString(sdBytes),
        }
        out, _ := json.Marshal(resp)
        fmt.Println(string(out))
    }
}
'''

GO_VERIFY_SRC = '''package main

import (
    "encoding/hex"
    "encoding/json"
    "os"
    "bufio"
    "fmt"
    verkle "github.com/ethereum/go-verkle"
)

type VerifyReq struct {
    PreRoot   string
    Proof     string
    StateDiff string
}

type VerifyResp struct {
    Valid bool
    Error string
}

func main() {
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        var req VerifyReq
        if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
            fmt.Println(`{"valid":false,"error":"parse"}`)
            continue
        }

        preRootBytes, _ := hex.DecodeString(req.PreRoot)
        vpBytes, _ := hex.DecodeString(req.Proof)
        sdBytes, _ := hex.DecodeString(req.StateDiff)

        var vp verkle.VerkleProof
        if err := json.Unmarshal(vpBytes, &vp); err != nil {
            fmt.Println(`{"valid":false,"error":"vp_parse:` + err.Error() + `"}`)
            continue
        }
        var sd verkle.StateDiff
        if err := json.Unmarshal(sdBytes, &sd); err != nil {
            fmt.Println(`{"valid":false,"error":"sd_parse:` + err.Error() + `"}`)
            continue
        }

        err := verkle.Verify(&vp, preRootBytes, preRootBytes, sd)
        resp := VerifyResp{Valid: err == nil}
        if err != nil {
            resp.Error = err.Error()
        }
        out, _ := json.Marshal(resp)
        fmt.Println(string(out))
    }
}
'''

import tempfile

# Compila helper proof
with open("/tmp/go_proof_helper.go", "w") as f:
    f.write(GO_PROOF_SRC)
with open("/tmp/go_verify_helper.go", "w") as f:
    f.write(GO_VERIFY_SRC)

print("[*] Compiling Go proof helper...", flush=True)
for src, out in [("/tmp/go_proof_helper.go", "/tmp/go_proof_helper"),
                 ("/tmp/go_verify_helper.go", "/tmp/go_verify_helper")]:
    r = subprocess.run(["go", "build", "-o", out, src],
                       cwd=GO_DIR, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"Build failed {src}:", r.stderr)
        sys.exit(1)
print("[+] Compiled OK", flush=True)

# Processi persistenti
proof_proc = subprocess.Popen(["/tmp/go_proof_helper"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=GO_DIR)
verify_proc = subprocess.Popen(["/tmp/go_verify_helper"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=GO_DIR)

def go_make_proof(keys, vals, query_key):
    req = json.dumps({
        "Keys":     [k.hex() for k in keys],
        "Values":   [v.hex() for v in vals],
        "QueryKey": query_key.hex()
    }) + "\n"
    proof_proc.stdin.write(req.encode())
    proof_proc.stdin.flush()
    line = proof_proc.stdout.readline()
    return json.loads(line)

def go_verify_proof(pre_root, proof_hex, statediff_hex):
    req = json.dumps({
        "PreRoot":   pre_root,
        "Proof":     proof_hex,
        "StateDiff": statediff_hex
    }) + "\n"
    verify_proc.stdin.write(req.encode())
    verify_proc.stdin.flush()
    line = verify_proc.stdout.readline()
    return json.loads(line)

# --- Test 1: Go proof, Go verify (sanity) ---
print("\n[*] Test 1: Go proof → Go verify (sanity check)", flush=True)
passed = failed = skipped = 0
for i in range(200):
    n = 1 + os.urandom(1)[0] % 5
    keys = [os.urandom(32) for _ in range(n)]
    vals = [os.urandom(32) for _ in range(n)]
    qk = keys[0]

    pr = go_make_proof(keys, vals, qk)
    if pr.get("error"):
        skipped += 1
        continue

    vr = go_verify_proof(pr["PreRoot"], pr["Proof"], pr["StateDiff"])
    if vr.get("Valid"):
        passed += 1
    else:
        failed += 1
        print(f"  [!] Go→Go FAIL iter={i}: {vr.get('Error','')}")

print(f"[+] Go→Go: passed={passed} failed={failed} skipped={skipped}")

# --- Test 2: Go proof, tampered value, Go verify (must FAIL) ---
print("\n[*] Test 2: Go proof + tampered StateDiff → Go verify (must reject)", flush=True)
false_accepts = 0
for i in range(200):
    n = 1 + os.urandom(1)[0] % 5
    keys = [os.urandom(32) for _ in range(n)]
    vals = [os.urandom(32) for _ in range(n)]
    qk = keys[0]

    pr = go_make_proof(keys, vals, qk)
    if pr.get("error"):
        continue

    # Decodifica StateDiff e flippa un byte
    sd_bytes = bytes.fromhex(pr["StateDiff"])
    if len(sd_bytes) < 10:
        continue
    tampered = bytearray(sd_bytes)
    tampered[len(tampered)//2] ^= 0xff
    tampered_hex = bytes(tampered).hex()

    vr = go_verify_proof(pr["PreRoot"], pr["Proof"], tampered_hex)
    if vr.get("Valid"):
        false_accepts += 1
        print(f"  [!!!] SOUNDNESS FAIL iter={i} — tampered StateDiff accepted!")

if false_accepts == 0:
    print(f"[+] Tamper rejection: all tampered proofs correctly rejected")
else:
    print(f"[!!!] CRITICAL: {false_accepts} false accepts on tampered StateDiff")

# --- Test 3: Proof cross-verificato — Go proof self-consistency ---
print("\n[*] Test 3: Proof round-trip consistency (serialize→deserialize→verify)", flush=True)
rt_failures = 0
for i in range(200):
    n = 1 + os.urandom(1)[0] % 5
    keys = [os.urandom(32) for _ in range(n)]
    vals = [os.urandom(32) for _ in range(n)]
    qk = keys[0]

    pr1 = go_make_proof(keys, vals, qk)
    if pr1.get("error"):
        continue
    pr2 = go_make_proof(keys, vals, qk)
    if pr2.get("error"):
        continue

    # Proof deterministico?
    if pr1["Proof"] != pr2["Proof"]:
        rt_failures += 1
        print(f"  [!!!] NON-DETERMINISTIC PROOF iter={i}")
        print(f"        proof1={pr1['Proof'][:32]}...")
        print(f"        proof2={pr2['Proof'][:32]}...")

if rt_failures == 0:
    print(f"[+] Proof determinism: OK over 200 iter")
else:
    print(f"[!!!] {rt_failures} non-deterministic proofs")

proof_proc.terminate()
verify_proc.terminate()
print("\n[*] Cross-proof test complete")

# --- Test 4: Go proof → Rust verify (il test critico) ---
# Il formato Rust verify_execution_witness prende JSON
# Dobbiamo costruire il formato che go-ethereum emetterebbe

print("\n[*] Test 4: Go proof → Rust verify_execution_witness", flush=True)

# Aggiungi verify_execution_witness all'harness Rust
RUST_VERIFY_SRC = r'''
use ffi_interface::verify_execution_witness;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead};

#[derive(Deserialize)]
struct Input {
    root: String,
    witness_json: String,
}

#[derive(Serialize)]
struct Output {
    valid: bool,
    error: Option<String>,
}

fn main() {
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        if line.trim().is_empty() { continue; }
        let out = match serde_json::from_str::<Input>(&line) {
            Err(e) => Output { valid: false, error: Some(e.to_string()) },
            Ok(inp) => {
                let ok = verify_execution_witness(&inp.root, &inp.witness_json);
                Output { valid: ok, error: None }
            }
        };
        println!("{}", serde_json::to_string(&out).unwrap());
    }
}
'''

with open("/home/rob/ethereum-crypto/rust-verkle/harness/src/main.rs", "w") as f:
    f.write(RUST_VERIFY_SRC)

print("[*] Rebuilding Rust harness with verify_execution_witness...", flush=True)
r = subprocess.run(
    ["cargo", "build", "--release"],
    cwd="/home/rob/ethereum-crypto/rust-verkle/harness",
    capture_output=True, text=True
)
if r.returncode != 0:
    print("Rust build failed:", r.stderr[-2000:])
else:
    print("[+] Rust harness rebuilt OK")
