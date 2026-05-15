# Finding: Nil Pointer Dereference in go-verkle `Verify()` via Crafted Execution Witness

## Severity
**High** — remotely triggerable panic (DoS) in go-ethereum verkle proof verification path.  
Post-Bogotá hardfork: any peer can crash a go-ethereum node by sending a block with a  
crafted execution witness containing `currentValue: null` + `newValue: non-null`.

## Affected Component
- Repository: `github.com/ethereum/go-verkle`
- Commit: `aa0a270` (HEAD/master as of 2025-05)
- File: `tree.go` lines 1269-1279, `proof_ipa.go` lines 590-610

## Reproducer
```go
// Canonical Rust test vector triggers panic in Go verifier
root := "2cf2ab8fed2dcfe2fa77da044ab16393dbdabbc65deea5fdf272107a039f2c60"
witness := `{"stateDiff":[{"stem":"0xab8fbede...","suffixDiffs":[{
    "suffix":97,
    "currentValue":null,        // <-- trigger condition
    "newValue":"0x2f08a146..."}  // <-- new value inserted
]}],"verkleProof":{...}}`

// Panics with: runtime error: invalid memory address or nil pointer dereference
// goroutine: LeafNode.updateCn → updateMultipleLeaves → InsertValuesAtStem
//            → PostStateTreeFromStateDiff → Verify
verkle.Verify(vp, rootBytes, rootBytes, sd)
```

## Root Cause
`PostStateTreeFromStateDiff` calls `InsertValuesAtStem` for stems where  
`suffixDiff.NewValue != nil`. When the stem is **absent in the pre-state**  
(currentValue=null), `InsertValuesAtStem` creates a new `LeafNode` via  
the internal tree insertion path. This LeafNode is allocated without  
initializing `c1`/`c2` commitment pointers (both remain `nil`).

Subsequently, `updateMultipleLeaves` → `updateCn(index, value, n.c1)` is  
called with `c = nil`, causing a nil pointer dereference at:
tree.go:1212: c.Add(c, &diff)  // c == nil → SIGSEGV

## Attack Scenario (post-Bogotá)
1. Attacker crafts execution witness with stem absent in pre-state but with newValue set
2. Sends block to go-ethereum node
3. Node calls `Verify()` during block validation
4. Panic crashes the node process → DoS

## Differential Context
- **Rust (rust-verkle)**: `verify_execution_witness()` accepts the same witness correctly  
  (no panic, returns `valid=true`)
- **Go (go-verkle)**: panics unconditionally on identical input

This cross-implementation divergence was discovered via differential testing  
using the canonical Rust test vector from `golang_proof_format.rs`.

## Fix
In `tree.go`, `updateMultipleLeaves` must guard against nil c1/c2:

```go
// Before calling updateCn, ensure c1/c2 are initialized
if n.c1 == nil {
    n.c1 = new(Point)
    n.c1.SetIdentity()
}
if n.c2 == nil {
    n.c2 = new(Point)
    n.c2.SetIdentity()
}
```

Or alternatively, `InsertValuesAtStem` should call `Commit()` on newly  
created LeafNodes before delegating to `updateMultipleLeaves`.

## Timeline
- Discovered: 2025-05 via differential fuzzing (go-verkle vs rust-verkle)
- Tool: verkle-diff-auditor (github.com/lau90eth/verkle-diff-auditor)
- Reporter: lau90eth

## Production Impact (aggiornamento)

- `gballet/go-ethereum` branch `kaustinen-with-shapella` usa `go-verkle v0.2.2`
- v0.2.2 ha **identico codice** a master sulla riga vulnerabile
- Il bug è presente in tutti i tag pubblicati
- Crash avviene anche su `oldC1.Set(n.c1)` (riga ~1265) prima ancora di `updateCn`,
  quando `n.c1 == nil` e `oldC1` viene inizializzato con `oldC1.Set(n.c1)`

## Fix minimo

```go
// tree.go ~1263 — prima del loop updateMultipleLeaves
if n.c1 == nil {
    n.c1 = new(Point)
    n.c1.SetIdentity()
}
if n.c2 == nil {
    n.c2 = new(Point)
    n.c2.SetIdentity()
}
```
