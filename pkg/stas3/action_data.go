package stas3

import (
	"encoding/binary"
	"encoding/hex"
)

// Action data selectors. The first byte of the action-data push (or the
// pushed opcode itself for the empty cases) determines the kind.
//
// Empty pushes are encoded compactly as opcodes:
//   - 0x00  (OP_0)  → passive empty
//   - 0x52  (OP_2)  → frozen empty
//
// Non-empty pushes carry a single selector byte followed by a payload:
//   - 0x01 → swap descriptor (32B requested_script_hash + 20B requested_pkh
//   - 4B rate_numerator (LE) + 4B rate_denominator (LE), plus
//     optional chained legs)
//   - 0x02 → frozen with inner payload (the prefix is dropped on unfreeze)
//   - 0x03 → custom application-defined record
//
// Anything else is reported as "custom" with the raw bytes preserved.
const (
	actionSelectorSwap   = 0x01
	actionSelectorFrozen = 0x02
	actionSelectorThree  = 0x03
)

// ActionKind names the canonical action_data variant. Apps that need raw
// bytes can read STASOutput.ActionData (full push hex) and re-decode.
const (
	ActionKindPassive = "passive"
	ActionKindFrozen  = "frozen"
	ActionKindSwap    = "swap"
	ActionKindCustom  = "custom"
)

// SwapDescriptor is the decoded first leg of a swap action data payload.
// Chained legs (the optional `next` pointer in the wire format) are not
// currently exposed; apps that need them can re-parse from ActionData.
type SwapDescriptor struct {
	// RequestedScriptHash is the SHA-256 of the counterparty class's
	// locking-script tail (owner + action_data slots stripped). It is
	// the universal asset-class identifier — apps wanting cross-class
	// matching compare this against any candidate UTXO's class_hash.
	RequestedScriptHash string `bson:"requestedScriptHash" json:"requestedScriptHash"`
	// RequestedPkh is the 20-byte hash160 the maker wants the
	// counterparty asset delivered to. Twenty zero bytes (a.k.a.
	// EMPTY_HASH160 in the SDK) is the "anyone-can-fill" sentinel.
	RequestedPkh string `bson:"requestedPkh"        json:"requestedPkh"`
	// RateNumerator and RateDenominator express the trade ratio as a
	// fraction. (0, 0) is the swap-cancel sentinel.
	RateNumerator   uint32 `bson:"rateNumerator"   json:"rateNumerator"`
	RateDenominator uint32 `bson:"rateDenominator" json:"rateDenominator"`
	// HasNext is true when the descriptor carries chained alternative
	// legs after the first 60-byte body. The full push is preserved in
	// STASOutput.ActionData if apps need to walk the chain.
	HasNext bool `bson:"hasNext,omitempty" json:"hasNext,omitempty"`
}

// swapLegBodySize is the byte count of one swap leg AFTER the selector
// byte: 32 (script hash) + 20 (pkh) + 4 (num) + 4 (den).
const swapLegBodySize = 60

// decodeActionData classifies a raw action-data push and, where
// applicable, decodes the first swap leg.
//
// `pushOpcode` is true when the push was a single byte that decoded as an
// opcode (OP_0 or OP_2) and `payload` is empty — needed to disambiguate
// "frozen empty" (OP_2) from "passive non-empty starting with 0x52".
func decodeActionData(payload []byte, pushOpcode byte) (kind string, frozen bool, swap *SwapDescriptor) {
	// Empty push paths first — encoded as bare opcodes.
	if len(payload) == 0 {
		switch pushOpcode {
		case op2: // 0x52 — frozen empty
			return ActionKindFrozen, true, nil
		default: // 0x00 / OP_FALSE / OP_0 — passive empty
			return ActionKindPassive, false, nil
		}
	}

	switch payload[0] {
	case actionSelectorSwap:
		// Swap descriptor: selector + 60-byte body, plus optional chained
		// legs. We surface the first leg for indexable filters and flag
		// presence of chained legs so apps know to inspect raw bytes.
		if len(payload) < 1+swapLegBodySize {
			return ActionKindCustom, false, nil
		}
		body := payload[1 : 1+swapLegBodySize]
		desc := &SwapDescriptor{
			RequestedScriptHash: hex.EncodeToString(body[0:32]),
			RequestedPkh:        hex.EncodeToString(body[32:52]),
			RateNumerator:       binary.LittleEndian.Uint32(body[52:56]),
			RateDenominator:     binary.LittleEndian.Uint32(body[56:60]),
			HasNext:             len(payload) > 1+swapLegBodySize,
		}
		return ActionKindSwap, false, desc

	case actionSelectorFrozen:
		// Frozen with inner payload — the inner payload may itself be a
		// swap or other selector (e.g., a frozen swap-marked UTXO).
		// Recurse one level so the swap leg is still queryable.
		if len(payload) > 1 {
			innerKind, _, innerSwap := decodeActionData(payload[1:], 0)
			// Frozen always wins for the kind label, but the inner swap
			// descriptor (if any) is still surfaced.
			if innerKind == ActionKindSwap {
				return ActionKindFrozen, true, innerSwap
			}
		}
		return ActionKindFrozen, true, nil

	case actionSelectorThree:
		// Reserved selector for application-defined freeze authority /
		// confiscation records (selector convention varies between
		// SDKs). Surface as custom — apps decode from raw bytes.
		return ActionKindCustom, false, nil

	default:
		return ActionKindCustom, false, nil
	}
}

// IsSwapCancelDescriptor returns true for the (0, 0) rate sentinel. A
// maker uses this to spend a swap-marked UTXO back to themselves.
func IsSwapCancelDescriptor(d *SwapDescriptor) bool {
	return d != nil && d.RateNumerator == 0 && d.RateDenominator == 0
}

// IsArbitratorFreeDescriptor returns true when the descriptor's
// RequestedPkh is the 20-byte zero sentinel — meaning any taker can
// settle the swap without the maker's signature at execute time.
func IsArbitratorFreeDescriptor(d *SwapDescriptor) bool {
	if d == nil {
		return false
	}
	for i := 0; i < 40; i += 2 {
		if d.RequestedPkh[i] != '0' || d.RequestedPkh[i+1] != '0' {
			return false
		}
	}
	return true
}
