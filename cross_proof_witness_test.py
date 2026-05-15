#!/usr/bin/env python3
"""
Test critico: verify_execution_witness cross-implementation
1. Rust verifica il witness canonico (sanity)
2. Go verifica lo stesso witness (cross-check)
3. Tamper su ogni campo → entrambi devono rifiutare
"""
import subprocess, json, os, sys

RUST_HARNESS = "/home/rob/ethereum-crypto/rust-verkle/harness/target/release/verkle-harness"
GO_DIR = "/home/rob/ethereum-crypto/go-verkle"

PREVIOUS_STATE_ROOT = "2cf2ab8fed2dcfe2fa77da044ab16393dbdabbc65deea5fdf272107a039f2c60"

EXECUTION_WITNESS = {
    "stateDiff": [
        {
            "stem": "0xab8fbede899caa6a95ece66789421c7777983761db3cfb33b5e47ba10f413b",
            "suffixDiffs": [
                {
                    "suffix": 97,
                    "currentValue": None,
                    "newValue": "0x2f08a1461ab75873a0f2d23170f46d3be2ade2a7f4ebf607fc53fb361cf85865"
                }
            ]
        }
    ],
    "verkleProof": {
        "otherStems": [],
        "depthExtensionPresent": "0x12",
        "commitmentsByPath": [
            "0x4900c9eda0b8f9a4ef9a2181ced149c9431b627797ab747ee9747b229579b583",
            "0x491dff71f13c89dac9aea22355478f5cfcf0af841b68e379a90aa77b8894c00e",
            "0x525d67511657d9220031586db9d41663ad592bbafc89bc763273a3c2eb0b19dc"
        ],
        "d": "0x5c6e856174962f2786f0711288c8ddd90b0c317db7769ab3485818460421f08c",
        "ipaProof": {
            "cl": [
                "0x4ff3c1e2a97b6bd0861a2866acecd2fd6d2e5949196429e409bfd4851339832e",
                "0x588cfd2b401c8afd04220310e10f7ccdf1144d2ef9191ee9f72d7d44ad1cf9d0",
                "0x0bb16d917ecdec316d38b92558d46450b21553673f38a824037716bfee067220",
                "0x2bdb51e80b9e43cc5011f4b51877f4d56232ce13035671f191bd4047baa11f3d",
                "0x130f6822a47533ed201f5f15b144648a727217980ca9e86237977b7f0fe8f41e",
                "0x2c4b83ccd0bb8ad8d370ab8308e11c95fb2020a6a62e71c9a1c08de2d32fc9f1",
                "0x4424bec140960c09fc97ee29dad2c3ff467b7e01a19ada43979c55c697b4f583",
                "0x5c8f76533d04c7b868e9d7fcaa901897c5f35b27552c3bf94f01951fae6fcd2a"
            ],
            "cr": [
                "0x31cb234eeff147546cabd033235c8f446812c7f44b597d9580a10bbecac9dd82",
                "0x6945048c033a452d346977ab306df4df653b6e7f3e0b75a705a650427ee30e88",
                "0x38ca3c4ebbee982301b6bafd55bc9e016a7c59af95e9666b56a0680ed1cd0673",
                "0x16160e96b0fb20d0c9c7d9ae76ca9c74300d34e05d3688315c0062204ab0d07b",
                "0x2bc96deadab15bc74546f8882d8b88c54ea0b62b04cb597bf5076fe25c53e43c",
                "0x301e407f62f0d1f6bf56f2e252ca89dd9f3bf09acbb0cca9230ecda24ac783b5",
                "0x3ce1800a2e3f10e641f3ef8a8aaacf6573e9e33f4cb5b429850271528ed3cd31",
                "0x471b1578afbd3f2762654d04db73c6a84e9770f3d6b8a189596fbad38fffa263"
            ],
            "finalEvaluation": "0x07ca48ff9f0fb458967f070c18e5cdf180e93212bf3efba6378384c5703a61fe"
        }
    }
}

# --- Rust verifier (processo persistente) ---
rust = subprocess.Popen(
    [RUST_HARNESS],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
)

def rust_verify(root, witness):
    req = json.dumps({"root": root, "witness_json": json.dumps(witness)}) + "\n"
    rust.stdin.write(req.encode())
    rust.stdin.flush()
    line = rust.stdout.readline()
    return json.loads(line)

# --- Go verifier ---
GO_VERIFY_SRC = '''package main
import (
    "encoding/hex"
    "encoding/json"
    "os"
    "bufio"
    "fmt"
    "strings"
    verkle "github.com/ethereum/go-verkle"
)
type Req struct {
    Root      string
    Witness   string
}
type Resp struct {
    Valid bool
    Error string
}
func main() {
    scanner := bufio.NewScanner(os.Stdin)
    scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
    for scanner.Scan() {
        var req Req
        if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
            out, _ := json.Marshal(Resp{Error: "parse:" + err.Error()})
            fmt.Println(string(out))
            continue
        }
        root := req.Root
        root = strings.TrimPrefix(root, "0x")
        rootBytes, err := hex.DecodeString(root)
        if err != nil || len(rootBytes) != 32 {
            out, _ := json.Marshal(Resp{Error: "root_decode"})
            fmt.Println(string(out))
            continue
        }

        // Parse witness JSON into VerkleProof + StateDiff
        var raw struct {
            VerkleProof verkle.VerkleProof `json:"verkleProof"`
            StateDiff   verkle.StateDiff   `json:"stateDiff"`
        }
        if err := json.Unmarshal([]byte(req.Witness), &raw); err != nil {
            out, _ := json.Marshal(Resp{Error: "witness_parse:" + err.Error()})
            fmt.Println(string(out))
            continue
        }

        err = verkle.Verify(&raw.VerkleProof, rootBytes, rootBytes, raw.StateDiff)
        resp := Resp{Valid: err == nil}
        if err != nil {
            resp.Error = err.Error()
        }
        out, _ := json.Marshal(resp)
        fmt.Println(string(out))
    }
}
'''

with open("/tmp/go_witness_verify.go", "w") as f:
    f.write(GO_VERIFY_SRC)

print("[*] Compiling Go witness verifier...", flush=True)
r = subprocess.run(["go", "build", "-o", "/tmp/go_witness_verify", "/tmp/go_witness_verify.go"],
                   cwd=GO_DIR, capture_output=True, text=True)
if r.returncode != 0:
    print("Build failed:", r.stderr)
    sys.exit(1)
print("[+] Compiled OK", flush=True)

go_ver = subprocess.Popen(
    ["/tmp/go_witness_verify"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd=GO_DIR
)

def go_verify(root, witness):
    req = json.dumps({"Root": root, "Witness": json.dumps(witness)}) + "\n"
    go_ver.stdin.write(req.encode())
    go_ver.stdin.flush()
    line = go_ver.stdout.readline()
    return json.loads(line)

# ============================================================
# TEST 1: Sanity — entrambi verificano il witness canonico
# ============================================================
print("\n[*] Test 1: Canonical witness verification", flush=True)

rr = rust_verify(PREVIOUS_STATE_ROOT, EXECUTION_WITNESS)
gr = go_verify(PREVIOUS_STATE_ROOT, EXECUTION_WITNESS)

print(f"  Rust: valid={rr.get('valid')} error={rr.get('error')}")
print(f"  Go:   valid={gr.get('Valid')} error={gr.get('Error')}")

if rr.get('valid') and gr.get('Valid'):
    print("[+] PASS: both implementations accept canonical witness")
elif rr.get('valid') and not gr.get('Valid'):
    print("[!!!] DIVERGENCE: Rust accepts, Go REJECTS — potential Go bug")
    print(f"      Go error: {gr.get('Error')}")
elif not rr.get('valid') and gr.get('Valid'):
    print("[!!!] DIVERGENCE: Go accepts, Rust REJECTS — potential Rust bug")
else:
    print("[~] Both reject (unexpected — check format)")

# ============================================================
# TEST 2: Tamper ogni campo critico → entrambi devono rifiutare
# ============================================================
print("\n[*] Test 2: Tamper attack on each proof field", flush=True)

import copy, random

def flip_hex(h):
    b = bytearray.fromhex(h.lstrip("0x"))
    b[0] ^= 0xff
    return "0x" + b.hex()

tamper_cases = []

# 2a: root sbagliato
w2a = copy.deepcopy(EXECUTION_WITNESS)
tamper_cases.append(("wrong_root", "0x" + os.urandom(32).hex(), w2a))

# 2b: d corrotto
w2b = copy.deepcopy(EXECUTION_WITNESS)
w2b["verkleProof"]["d"] = flip_hex(w2b["verkleProof"]["d"])
tamper_cases.append(("tampered_d", PREVIOUS_STATE_ROOT, w2b))

# 2c: finalEvaluation corrotto
w2c = copy.deepcopy(EXECUTION_WITNESS)
w2c["verkleProof"]["ipaProof"]["finalEvaluation"] = flip_hex(
    w2c["verkleProof"]["ipaProof"]["finalEvaluation"])
tamper_cases.append(("tampered_finalEval", PREVIOUS_STATE_ROOT, w2c))

# 2d: primo cl corrotto
w2d = copy.deepcopy(EXECUTION_WITNESS)
w2d["verkleProof"]["ipaProof"]["cl"][0] = flip_hex(
    w2d["verkleProof"]["ipaProof"]["cl"][0])
tamper_cases.append(("tampered_cl[0]", PREVIOUS_STATE_ROOT, w2d))

# 2e: primo cr corrotto
w2e = copy.deepcopy(EXECUTION_WITNESS)
w2e["verkleProof"]["ipaProof"]["cr"][0] = flip_hex(
    w2e["verkleProof"]["ipaProof"]["cr"][0])
tamper_cases.append(("tampered_cr[0]", PREVIOUS_STATE_ROOT, w2e))

# 2f: newValue corrotto
w2f = copy.deepcopy(EXECUTION_WITNESS)
w2f["stateDiff"][0]["suffixDiffs"][0]["newValue"] = flip_hex(
    w2f["stateDiff"][0]["suffixDiffs"][0]["newValue"])
tamper_cases.append(("tampered_newValue", PREVIOUS_STATE_ROOT, w2f))

# 2g: stem corrotto
w2g = copy.deepcopy(EXECUTION_WITNESS)
w2g["stateDiff"][0]["stem"] = flip_hex(w2g["stateDiff"][0]["stem"])
tamper_cases.append(("tampered_stem", PREVIOUS_STATE_ROOT, w2g))

# 2h: commitment[0] corrotto
w2h = copy.deepcopy(EXECUTION_WITNESS)
w2h["verkleProof"]["commitmentsByPath"][0] = flip_hex(
    w2h["verkleProof"]["commitmentsByPath"][0])
tamper_cases.append(("tampered_commitment[0]", PREVIOUS_STATE_ROOT, w2h))

rust_false_accepts = 0
go_false_accepts = 0
divergences = 0

for name, root, witness in tamper_cases:
    rr = rust_verify(root, witness)
    gr = go_verify(root, witness)

    r_ok = rr.get('valid', False)
    g_ok = gr.get('Valid', False)

    status = "OK" if (not r_ok and not g_ok) else ""

    if r_ok:
        rust_false_accepts += 1
        status = f"[!!!] RUST FALSE ACCEPT"
    if g_ok:
        go_false_accepts += 1
        status = f"[!!!] GO FALSE ACCEPT"
    if r_ok != g_ok:
        divergences += 1
        status = f"[!!!] DIVERGENCE rust={r_ok} go={g_ok}"

    print(f"  {name:30s} rust={r_ok} go={g_ok} {status}")

print(f"\n  rust_false_accepts={rust_false_accepts}")
print(f"  go_false_accepts={go_false_accepts}")
print(f"  divergences={divergences}")

if divergences > 0:
    print("[!!!] CRITICAL: Go and Rust disagree on tampered witnesses")
elif rust_false_accepts > 0 or go_false_accepts > 0:
    print("[!!!] CRITICAL: false accepts detected")
else:
    print("[+] PASS: all tampered witnesses correctly rejected by both")

rust.terminate()
go_ver.terminate()
