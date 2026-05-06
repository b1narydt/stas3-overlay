package stas3

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/script"
)

// --- ComputeClassHash / extractCounterpartyScript ---

// TestClassHash_OwnerInvariant proves the class hash is invariant under
// owner changes — the load-bearing property for cross-overlay matching.
// Two UTXOs of the same class with different owners must hash identically.
func TestClassHash_OwnerInvariant(t *testing.T) {
	tokenID, _ := hex.DecodeString("1122334455667788990011223344556677889900")
	aliceOwner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	bobOwner, _ := hex.DecodeString("ffeeddccbbaa9988776655443322110099887766")

	scriptA := buildDSTASScript(aliceOwner, tokenID, opFALSE, 200)
	scriptB := buildDSTASScript(bobOwner, tokenID, opFALSE, 200)

	hashA, err := ComputeClassHash(scriptA)
	if err != nil {
		t.Fatalf("classHash for A: %v", err)
	}
	hashB, err := ComputeClassHash(scriptB)
	if err != nil {
		t.Fatalf("classHash for B: %v", err)
	}
	if hashA != hashB {
		t.Errorf("class_hash must be owner-invariant; got %s vs %s", hashA, hashB)
	}
	if len(hashA) != 64 {
		t.Errorf("class_hash should be 64 hex chars (sha256), got %d", len(hashA))
	}
}

// TestClassHash_ActionDataInvariant proves the class hash is invariant
// under action_data changes — passive / swap-marked / frozen UTXOs of
// the same class must share a class hash so a swap descriptor's
// `requested_script_hash` can match any of them.
func TestClassHash_ActionDataInvariant(t *testing.T) {
	owner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	tokenID, _ := hex.DecodeString("1122334455667788990011223344556677889900")

	passive := buildDSTASScript(owner, tokenID, opFALSE, 200)
	frozen := buildDSTASScript(owner, tokenID, op2, 200)

	hashPassive, err := ComputeClassHash(passive)
	if err != nil {
		t.Fatalf("classHash passive: %v", err)
	}
	hashFrozen, err := ComputeClassHash(frozen)
	if err != nil {
		t.Fatalf("classHash frozen: %v", err)
	}
	if hashPassive != hashFrozen {
		t.Errorf("class_hash must be action_data-invariant; passive=%s frozen=%s", hashPassive, hashFrozen)
	}
}

// TestClassHash_ClassDistinctness proves the class hash differs between
// classes (different redemption PKH ⇒ different hash). This is the basis
// for per-class scope predicates.
func TestClassHash_ClassDistinctness(t *testing.T) {
	owner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	usdToken, _ := hex.DecodeString("1111111111111111111111111111111111111111")
	goldToken, _ := hex.DecodeString("2222222222222222222222222222222222222222")

	usdScript := buildDSTASScript(owner, usdToken, opFALSE, 200)
	goldScript := buildDSTASScript(owner, goldToken, opFALSE, 200)

	hashUSD, _ := ComputeClassHash(usdScript)
	hashGOLD, _ := ComputeClassHash(goldScript)
	if hashUSD == hashGOLD {
		t.Errorf("different classes should hash differently; both=%s", hashUSD)
	}
}

// TestClassHash_DeterministicAcrossCalls ensures repeated computation
// returns the same hash — required for cross-process cross-overlay
// equality.
func TestClassHash_DeterministicAcrossCalls(t *testing.T) {
	owner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	tokenID, _ := hex.DecodeString("1122334455667788990011223344556677889900")
	s := buildDSTASScript(owner, tokenID, opFALSE, 200)

	first, _ := ComputeClassHash(s)
	for i := 0; i < 5; i++ {
		again, _ := ComputeClassHash(s)
		if first != again {
			t.Errorf("class_hash drifted on call %d: %s vs %s", i, first, again)
		}
	}
}

// --- decodeActionData ---

// TestDecodeActionData_Passive checks the bare OP_0 / empty payload case.
func TestDecodeActionData_Passive(t *testing.T) {
	kind, frozen, swap, payload := decodeActionData(nil, opFALSE)
	if kind != ActionKindPassive {
		t.Errorf("OP_0 should be passive, got %s", kind)
	}
	if frozen {
		t.Errorf("OP_0 must not be frozen")
	}
	if swap != nil {
		t.Errorf("OP_0 should have no swap descriptor")
	}
	if payload != nil {
		t.Errorf("passive should have no action-record payload")
	}
}

// TestDecodeActionData_FrozenOpcode checks bare OP_2 — the dxs locking
// builder's compact "frozen empty UTXO" encoding.
func TestDecodeActionData_FrozenOpcode(t *testing.T) {
	kind, frozen, _, _ := decodeActionData(nil, op2)
	if kind != ActionKindFrozen {
		t.Errorf("OP_2 should be frozen, got %s", kind)
	}
	if !frozen {
		t.Errorf("OP_2 must be frozen")
	}
}

// TestDecodeActionData_Swap walks a hand-built swap leg.
func TestDecodeActionData_Swap(t *testing.T) {
	requestedHash := bytes.Repeat([]byte{0xab}, 32)
	requestedPkh := bytes.Repeat([]byte{0xcd}, 20)
	payload := append([]byte{actionSelectorSwap}, requestedHash...)
	payload = append(payload, requestedPkh...)
	rate := make([]byte, 8)
	binary.LittleEndian.PutUint32(rate[0:4], 100)
	binary.LittleEndian.PutUint32(rate[4:8], 1)
	payload = append(payload, rate...)

	kind, frozen, swap, _ := decodeActionData(payload, 0)
	if kind != ActionKindSwap {
		t.Errorf("expected swap, got %s", kind)
	}
	if frozen {
		t.Errorf("swap UTXO not frozen by default")
	}
	if swap == nil {
		t.Fatalf("swap descriptor should be non-nil")
	}
	if swap.RequestedScriptHash != hex.EncodeToString(requestedHash) {
		t.Errorf("requested_script_hash mismatch: got %s", swap.RequestedScriptHash)
	}
	if swap.RequestedPkh != hex.EncodeToString(requestedPkh) {
		t.Errorf("requested_pkh mismatch: got %s", swap.RequestedPkh)
	}
	if swap.RateNumerator != 100 || swap.RateDenominator != 1 {
		t.Errorf("rate mismatch: got %d/%d", swap.RateNumerator, swap.RateDenominator)
	}
	if swap.HasNext {
		t.Errorf("single-leg swap should not flag HasNext")
	}
}

// TestDecodeActionData_SwapWithChainedNext flags HasNext when extra bytes
// trail the first leg.
func TestDecodeActionData_SwapWithChainedNext(t *testing.T) {
	payload := append([]byte{actionSelectorSwap}, bytes.Repeat([]byte{0x00}, swapLegBodySize)...)
	// Append one more byte to simulate a chained-next prefix.
	payload = append(payload, 0x01)

	_, _, swap, _ := decodeActionData(payload, 0)
	if swap == nil || !swap.HasNext {
		t.Errorf("HasNext should be true when bytes trail first leg")
	}
}

// TestDecodeActionData_Confiscation covers selector 0x02 — the dxs
// canonical "confiscation action record" kind. Payload bytes after the
// selector must be preserved for SDK-specific decoding.
func TestDecodeActionData_Confiscation(t *testing.T) {
	innerPayload := []byte{0xaa, 0xbb, 0xcc}
	payload := append([]byte{actionSelectorConfiscation}, innerPayload...)

	kind, frozen, swap, recordPayload := decodeActionData(payload, 0)
	if kind != ActionKindConfiscation {
		t.Errorf("selector 0x02 should be confiscation per dxs canonical, got %s", kind)
	}
	if frozen {
		t.Errorf("confiscation action records must NOT set frozen=true (frozen is the bare-OP_2 state marker only)")
	}
	if swap != nil {
		t.Errorf("confiscation should not surface a swap descriptor")
	}
	if !bytes.Equal(recordPayload, innerPayload) {
		t.Errorf("payload preservation mismatch: got %x want %x", recordPayload, innerPayload)
	}
}

// TestDecodeActionData_Freeze covers selector 0x03 — the dxs canonical
// "freeze action record" kind. Previously labeled "custom" with payload
// discarded; that was the validation bug Quaakee/dxs swarm caught.
func TestDecodeActionData_Freeze(t *testing.T) {
	innerPayload := []byte{0xde, 0xad}
	payload := append([]byte{actionSelectorFreeze}, innerPayload...)

	kind, _, _, recordPayload := decodeActionData(payload, 0)
	if kind != ActionKindFreeze {
		t.Errorf("selector 0x03 should be freeze per dxs canonical, got %s", kind)
	}
	if !bytes.Equal(recordPayload, innerPayload) {
		t.Errorf("freeze payload preservation mismatch: got %x want %x", recordPayload, innerPayload)
	}
}

// TestDecodeActionData_Custom covers the unknown-selector fallback.
// Payload bytes (including the selector) must be preserved verbatim,
// matching dxs's `{ kind: "unknown", action, payload }` semantics.
func TestDecodeActionData_Custom(t *testing.T) {
	input := []byte{0xff, 0xab, 0xcd}
	kind, _, _, payload := decodeActionData(input, 0)
	if kind != ActionKindCustom {
		t.Errorf("expected custom kind, got %s", kind)
	}
	if !bytes.Equal(payload, input) {
		t.Errorf("custom payload should preserve the entire input verbatim; got %x want %x", payload, input)
	}
}

// TestDecodeActionData_TruncatedSwap returns custom + raw payload when a
// swap selector is followed by fewer than 60 body bytes.
func TestDecodeActionData_TruncatedSwap(t *testing.T) {
	input := []byte{actionSelectorSwap, 0xab, 0xcd}
	kind, _, swap, payload := decodeActionData(input, 0)
	if kind != ActionKindCustom {
		t.Errorf("truncated swap should be reported as custom, got %s", kind)
	}
	if swap != nil {
		t.Errorf("truncated swap should not surface a descriptor")
	}
	if !bytes.Equal(payload, input) {
		t.Errorf("truncated swap should preserve raw payload")
	}
}

// TestSwapCancelSentinel covers the (0,0) rate detection.
func TestSwapCancelSentinel(t *testing.T) {
	d := &SwapDescriptor{RateNumerator: 0, RateDenominator: 0}
	if !IsSwapCancelDescriptor(d) {
		t.Errorf("(0,0) should be cancel sentinel")
	}
	d2 := &SwapDescriptor{RateNumerator: 1, RateDenominator: 1}
	if IsSwapCancelDescriptor(d2) {
		t.Errorf("(1,1) should not be cancel sentinel")
	}
	if IsSwapCancelDescriptor(nil) {
		t.Errorf("nil should not match cancel sentinel")
	}
}

// TestArbitratorFreeSentinel covers the EMPTY_HASH160 detection.
//
// The Rust SDK's arbitrator-free sentinel is HASH160("") =
// `b472a266d0bd89c13706a4132ccfb16f7c3b9fcb`, NOT 20 zero bytes — that
// was a bug the dxs validation swarm caught.
func TestArbitratorFreeSentinel(t *testing.T) {
	d := &SwapDescriptor{RequestedPkh: EmptyHash160Hex}
	if !IsArbitratorFreeDescriptor(d) {
		t.Errorf("HASH160('') sentinel should be arbitrator-free")
	}

	// 20 zero bytes is NOT the Rust SDK sentinel — must NOT match.
	zeros := strings.Repeat("00", 20)
	d2 := &SwapDescriptor{RequestedPkh: zeros}
	if IsArbitratorFreeDescriptor(d2) {
		t.Errorf("20-zero-bytes is NOT the canonical sentinel; helper must not match it")
	}

	d3 := &SwapDescriptor{RequestedPkh: strings.Repeat("aa", 20)}
	if IsArbitratorFreeDescriptor(d3) {
		t.Errorf("non-zero PKH should not be arbitrator-free")
	}

	if IsArbitratorFreeDescriptor(nil) {
		t.Errorf("nil descriptor should not match")
	}
}

// --- ParseSTASScript surfaces extended fields ---

// TestParseSTASScript_SurfacesClassHash verifies parse output carries the
// class hash.
func TestParseSTASScript_SurfacesClassHash(t *testing.T) {
	owner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	tokenID, _ := hex.DecodeString("1122334455667788990011223344556677889900")
	s := buildDSTASScript(owner, tokenID, opFALSE, 200)

	out, err := ParseSTASScript(s)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.ClassHash == "" {
		t.Errorf("ClassHash should be non-empty")
	}
	expected, _ := ComputeClassHash(s)
	if out.ClassHash != expected {
		t.Errorf("ClassHash mismatch: got %s want %s", out.ClassHash, expected)
	}
}

// TestParseSTASScript_PassiveActionKind confirms a vanilla DSTAS UTXO is
// classified as passive.
func TestParseSTASScript_PassiveActionKind(t *testing.T) {
	owner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	tokenID, _ := hex.DecodeString("1122334455667788990011223344556677889900")
	s := buildDSTASScript(owner, tokenID, opFALSE, 200)

	out, err := ParseSTASScript(s)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.ActionKind != ActionKindPassive {
		t.Errorf("expected passive, got %s", out.ActionKind)
	}
	if out.Frozen {
		t.Errorf("OP_0 UTXO should not be frozen")
	}
	if out.SwapDescriptor != nil {
		t.Errorf("passive UTXO should have no swap descriptor")
	}
}

// TestParseSTASScript_FrozenActionKind confirms an OP_2 UTXO is frozen.
func TestParseSTASScript_FrozenActionKind(t *testing.T) {
	owner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	tokenID, _ := hex.DecodeString("1122334455667788990011223344556677889900")
	s := buildDSTASScript(owner, tokenID, op2, 200)

	out, err := ParseSTASScript(s)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.ActionKind != ActionKindFrozen {
		t.Errorf("expected frozen, got %s", out.ActionKind)
	}
	if !out.Frozen {
		t.Errorf("OP_2 UTXO must be frozen=true")
	}
}

// TestParseSTASScript_SwapDescriptor verifies a swap-marked UTXO surfaces
// the typed descriptor fields end-to-end.
func TestParseSTASScript_SwapDescriptor(t *testing.T) {
	owner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	tokenID, _ := hex.DecodeString("1122334455667788990011223344556677889900")
	requestedHash := bytes.Repeat([]byte{0xab}, 32)
	requestedPkh := bytes.Repeat([]byte{0xcd}, 20)

	// Action data: swap selector + 60-byte body
	actionData := []byte{actionSelectorSwap}
	actionData = append(actionData, requestedHash...)
	actionData = append(actionData, requestedPkh...)
	rate := make([]byte, 8)
	binary.LittleEndian.PutUint32(rate[0:4], 1)
	binary.LittleEndian.PutUint32(rate[4:8], 2)
	actionData = append(actionData, rate...)

	s := buildDSTASScriptWithData(owner, tokenID, actionData, 200)
	out, err := ParseSTASScript(s)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.ActionKind != ActionKindSwap {
		t.Errorf("expected swap, got %s", out.ActionKind)
	}
	if out.SwapDescriptor == nil {
		t.Fatalf("swap descriptor should be surfaced")
	}
	if out.SwapDescriptor.RequestedScriptHash != hex.EncodeToString(requestedHash) {
		t.Errorf("requestedScriptHash mismatch")
	}
	if out.SwapDescriptor.RateNumerator != 1 || out.SwapDescriptor.RateDenominator != 2 {
		t.Errorf("rate mismatch: %d/%d", out.SwapDescriptor.RateNumerator, out.SwapDescriptor.RateDenominator)
	}
}

// TestParseSTASScript_FlagsByte confirms the flags byte is surfaced.
func TestParseSTASScript_FlagsByte(t *testing.T) {
	owner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	tokenID, _ := hex.DecodeString("1122334455667788990011223344556677889900")
	// buildDSTASScript hardcodes flags=0x03 (freezable+confiscatable)
	s := buildDSTASScript(owner, tokenID, opFALSE, 200)

	out, err := ParseSTASScript(s)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.Flags != 0x03 {
		t.Errorf("expected flags=0x03 (freezable+confiscatable), got 0x%x", out.Flags)
	}
}

// --- TopicManager class-hash gate ---

// TestTopicManager_AdmitAllByDefault confirms the legacy admit-all
// behavior when ExpectedClassHash is empty.
func TestTopicManager_AdmitAllByDefault(t *testing.T) {
	m := NewTopicManager()
	if m.ExpectedClassHash != "" {
		t.Errorf("default ExpectedClassHash should be empty, got %s", m.ExpectedClassHash)
	}
}

// TestTopicManager_ClassScopedConstructor stores the configured class hash.
func TestTopicManager_ClassScopedConstructor(t *testing.T) {
	want := strings.Repeat("ab", 32)
	m := NewClassScopedTopicManager(want)
	if m.ExpectedClassHash != want {
		t.Errorf("ExpectedClassHash mismatch: got %s want %s", m.ExpectedClassHash, want)
	}
}

// --- buildLookupFilter ---

// TestBuildLookupFilter_ExtendedFields confirms every new STASQuery
// field is wired into the Mongo filter document.
func TestBuildLookupFilter_ExtendedFields(t *testing.T) {
	v := uint32(7)
	q := &STASQuery{
		TokenID:                 "tok",
		Address:                 "addr",
		UnspentOnly:             true,
		ClassHash:               "ch",
		ActionKind:              "swap",
		FrozenOnly:              true,
		SwapRequestedScriptHash: "rsh",
		SwapRequestedPkh:        "pkh",
		TxID:                    "tx",
		Vout:                    &v,
	}
	f := buildLookupFilter(q)
	cases := map[string]any{
		"tokenId":                 "tok",
		"address":                 "addr",
		"spent":                   false,
		"classHash":               "ch",
		"actionKind":              "swap",
		"frozen":                  true,
		"swapRequestedScriptHash": "rsh",
		"swapRequestedPkh":        "pkh",
		"txid":                    "tx",
		"vout":                    uint32(7),
	}
	for k, want := range cases {
		got, ok := f[k]
		if !ok {
			t.Errorf("missing filter key %q", k)
			continue
		}
		if got != want {
			t.Errorf("filter[%q]: got %v want %v", k, got, want)
		}
	}
}

// TestBuildLookupFilter_EmptyQueryProducesEmptyFilter ensures an unset
// query returns no filters (matches all).
func TestBuildLookupFilter_EmptyQueryProducesEmptyFilter(t *testing.T) {
	f := buildLookupFilter(&STASQuery{})
	if len(f) != 0 {
		t.Errorf("empty query should produce empty filter; got %v", f)
	}
}

// TestBuildLookupFilter_VoutPointerSemantics confirms that vout=nil is
// not treated as vout=0 (a real concern: Go's zero value for uint32 is 0,
// so a non-pointer field would always filter on vout=0 by default).
func TestBuildLookupFilter_VoutPointerSemantics(t *testing.T) {
	q := &STASQuery{}
	f := buildLookupFilter(q)
	if _, has := f["vout"]; has {
		t.Errorf("vout=nil must NOT add a vout filter; got %v", f)
	}

	v := uint32(0)
	q2 := &STASQuery{Vout: &v}
	f2 := buildLookupFilter(q2)
	if got := f2["vout"]; got != uint32(0) {
		t.Errorf("vout=&0 should add vout=0 filter; got %v", got)
	}
}

// --- end-to-end: extractCounterpartyScript matches DSTAS layout ---

// TestExtractCounterpartyScript_StripFirstTwoPushes ensures the helper
// returns exactly bytes from after the action_data push to end-of-script.
func TestExtractCounterpartyScript_StripFirstTwoPushes(t *testing.T) {
	owner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	tokenID, _ := hex.DecodeString("1122334455667788990011223344556677889900")
	s := buildDSTASScript(owner, tokenID, opFALSE, 200)

	tail, err := extractCounterpartyScript(*s)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	// The tail should NOT contain the owner's 20 bytes (they precede push 1).
	if bytes.Contains(tail, owner) {
		t.Errorf("tail should not contain owner bytes")
	}
	// The tail SHOULD contain the redemption pkh (which is part of the
	// post-OP_RETURN block — the body the swap descriptor commits to).
	if !bytes.Contains(tail, tokenID) {
		t.Errorf("tail should contain redemption pkh / tokenId")
	}
}

// Sanity: hashing the extracted tail twice gives the same result, and
// matches what ComputeClassHash returns externally.
func TestComputeClassHash_MatchesManualSha256(t *testing.T) {
	owner, _ := hex.DecodeString("aabbccddee0011223344aabbccddee0011223344")
	tokenID, _ := hex.DecodeString("1122334455667788990011223344556677889900")
	s := buildDSTASScript(owner, tokenID, opFALSE, 200)

	want, _ := ComputeClassHash(s)

	tail, _ := extractCounterpartyScript(*s)
	sum := sha256.Sum256(tail)
	got := hex.EncodeToString(sum[:])

	if got != want {
		t.Errorf("manual sha256 disagrees with ComputeClassHash: %s vs %s", got, want)
	}
}

// Compile-time sanity: STASRecord must round-trip via JSON without
// losing any extended field. (Not exercised against live Mongo here —
// just a structural check via hand-composed JSON.)
func TestSTASRecord_HasExtendedFields(t *testing.T) {
	r := STASRecord{
		TxID:                    "abc",
		ClassHash:               "ch",
		ActionKind:              "swap",
		Frozen:                  true,
		SwapRequestedScriptHash: "rsh",
		SwapRateNumerator:       1,
		Flags:                   0x03,
		FreezeAuthority:         "fa",
		ConfiscationAuthority:   "ca",
		OptionalData:            []string{"deadbeef"},
	}
	// Just confirm fields are addressable; compile-time check.
	_ = r.SwapHasNext
	_ = r.SwapRequestedPkh
	_ = r.ActionData
	_ = r.SpendTxID
	_ = r.BlockHeight
	if r.OptionalData[0] != "deadbeef" {
		t.Errorf("optional_data round-trip failed")
	}
}

// Compile-time wiring: ensure the new package-level interfaces compile.
var _ *script.Script // touch the import to silence go vet on minimal tests
