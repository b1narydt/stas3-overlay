package stas3

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/bsv-blockchain/go-sdk/script"
)

// ComputeClassHash returns the universal STAS3 asset-class identifier for
// a locking script. It is the SHA-256 of the script's tail with the first
// two pushes (owner + action_data) stripped — i.e. everything from the
// covenant body onward, including the redemption pkh, flags byte, service
// fields, and optional_data.
//
// This hash is:
//   - deterministic — every overlay computes the same value for the same class
//   - owner-independent — alice's UTXO and bob's UTXO of the same class hash identically
//   - action_data-independent — passive / swap-marked / frozen variants share the hash
//   - the value committed in swap descriptors as `requested_script_hash`
//
// Apps doing cross-overlay swap discovery use this hash as the routing
// key: query any overlay for "give me UTXOs whose class_hash == H_GOLD"
// or "give me swap-marked UTXOs whose requested_script_hash == H_GOLD".
//
// Returns an empty string and a non-nil error if the script is not a
// recognized STAS3 layout (no two parseable pushes followed by a body).
func ComputeClassHash(s *script.Script) (string, error) {
	if s == nil {
		return "", ErrNotSTAS
	}
	b := *s
	tail, err := extractCounterpartyScript(b)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(tail)
	return hex.EncodeToString(sum[:]), nil
}

// extractCounterpartyScript returns the bytes of the locking script with
// the first two pushdata sequences (owner field, action_data field)
// stripped. It mirrors `extractDstasCounterpartyScript` in the canonical
// SDKs.
func extractCounterpartyScript(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, ErrTooShort
	}
	// Skip owner push (push 1).
	end1 := skipPush(b, 0)
	if end1 < 0 || end1 >= len(b) {
		return nil, ErrTooShort
	}
	// Skip action_data push (push 2). The action_data slot is *always*
	// a single push (data push or single-byte opcode like OP_0 / OP_2).
	end2 := skipPush(b, end1)
	if end2 < 0 || end2 >= len(b) {
		return nil, ErrTooShort
	}
	return b[end2:], nil
}
