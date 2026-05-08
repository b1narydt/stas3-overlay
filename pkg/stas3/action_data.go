package stas3

import (
	"encoding/binary"
	"encoding/hex"
)

// Action data selectors. The first byte of the action-data push (or the
// pushed opcode itself for the empty cases) determines the kind. Selector
// values mirror the canonical dxs-bsv-token-sdk encoding at
// `src/script/dstas-action-data.ts:3-7` — apps that interoperate with
// dxs-emitted scripts will see consistent kind labels.
//
// Empty action data is encoded compactly as bare opcodes:
//   - 0x00  (OP_0)  → passive empty UTXO
//   - 0x52  (OP_2)  → frozen empty UTXO (dxs locking-builder convention)
//
// Non-empty pushes carry a single selector byte followed by a payload:
//   - 0x01 → swap descriptor (32B requested_script_hash + 20B requested_pkh
//   - 4B rate_numerator (LE) + 4B rate_denominator (LE), plus
//     optional chained legs)
//   - 0x02 → confiscation action record (payload application-defined)
//   - 0x03 → freeze action record (payload application-defined)
//
// Anything else is reported as "custom" with the raw payload preserved.
const (
	actionSelectorSwap         byte = 0x01
	actionSelectorConfiscation byte = 0x02
	actionSelectorFreeze       byte = 0x03
)

// ActionKind names the canonical action_data variant. Labels match the
// dxs SDK enum so apps can route on a single set of names.
//
// "frozen" is a UTXO state (encoded as bare OP_2 in the locking script)
// and is distinct from "confiscation"/"freeze" which are action records
// embedded as data pushes with their respective selector bytes.
const (
	ActionKindPassive      = "passive"
	ActionKindFrozen       = "frozen"
	ActionKindSwap         = "swap"
	ActionKindConfiscation = "confiscation"
	ActionKindFreeze       = "freeze"
	ActionKindCustom       = "custom"
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
	// counterparty asset delivered to. The sentinel value
	// [EmptyHash160Hex] = `HASH160("")` flags the offer as
	// "anyone-can-fill" (the engine accepts OP_FALSE on the maker's
	// leg) — a stas3-rs extension introduced in v0.2.0+ to support
	// arbitrator-free swap offers emitted by Runar covenant contracts
	// that hold no private key. dxs canonical does not emit this
	// sentinel, but the on-chain wire format is identical and overlays
	// indexing offers from either SDK can flag arbitrator-free entries
	// via [IsArbitratorFreeDescriptor].
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
// applicable, decodes the first swap leg. Returns the canonical kind
// label, a frozen-state bool (true only for bare-OP_2 frozen-empty
// UTXOs), the swap descriptor (when kind == swap), and the action-record
// payload bytes (preserved for confiscation / freeze / custom kinds so
// apps can decode SDK-specific structures).
//
// `pushOpcode` carries the script-byte that produced this push when the
// payload is empty — needed to disambiguate "frozen empty" (OP_2) from
// "passive empty" (OP_0) at the script-byte level.
func decodeActionData(payload []byte, pushOpcode byte) (kind string, frozen bool, swap *SwapDescriptor, actionPayload []byte) {
	// Empty push paths — encoded as bare opcodes. dxs's locking builder
	// uses OP_2 to compactly mark "frozen empty UTXO" — preserve that
	// state-marker semantic. OP_0 (and any other bare opcode that pushes
	// an empty buffer) is treated as passive.
	if len(payload) == 0 {
		switch pushOpcode {
		case op2: // 0x52 — frozen empty UTXO
			return ActionKindFrozen, true, nil, nil
		default: // 0x00 / OP_FALSE / OP_0 — passive empty UTXO
			return ActionKindPassive, false, nil, nil
		}
	}

	switch payload[0] {
	case actionSelectorSwap:
		// Swap descriptor: selector + 60-byte body, plus optional chained
		// legs. We surface the first leg for indexable filters and flag
		// presence of chained legs so apps know to inspect raw bytes.
		if len(payload) < 1+swapLegBodySize {
			// Truncated leg — preserve raw payload as custom so apps can
			// see what the upstream produced. Stricter dxs decoders
			// throw here; we are deliberately permissive at the index
			// layer so a malformed UTXO is still queryable.
			return ActionKindCustom, false, nil, append([]byte(nil), payload...)
		}
		body := payload[1 : 1+swapLegBodySize]
		desc := &SwapDescriptor{
			RequestedScriptHash: hex.EncodeToString(body[0:32]),
			RequestedPkh:        hex.EncodeToString(body[32:52]),
			RateNumerator:       binary.LittleEndian.Uint32(body[52:56]),
			RateDenominator:     binary.LittleEndian.Uint32(body[56:60]),
			HasNext:             len(payload) > 1+swapLegBodySize,
		}
		return ActionKindSwap, false, desc, nil

	case actionSelectorConfiscation:
		// Action record for a confiscation operation (dxs canonical).
		// The payload after the selector is application-defined; we
		// preserve it verbatim so callers can decode SDK-specific
		// inner structures.
		return ActionKindConfiscation, false, nil, append([]byte(nil), payload[1:]...)

	case actionSelectorFreeze:
		// Action record for a freeze operation (dxs canonical).
		return ActionKindFreeze, false, nil, append([]byte(nil), payload[1:]...)

	default:
		// Unknown selector — preserve the entire payload (selector +
		// remainder) for caller-side inspection. Matches dxs decoder's
		// `{ kind: "unknown", action, payload }` semantics.
		return ActionKindCustom, false, nil, append([]byte(nil), payload...)
	}
}

// IsSwapCancelDescriptor returns true for the (0, 0) rate sentinel. A
// maker uses this to spend a swap-marked UTXO back to themselves.
func IsSwapCancelDescriptor(d *SwapDescriptor) bool {
	return d != nil && d.RateNumerator == 0 && d.RateDenominator == 0
}

// EmptyHash160Hex is the canonical Rust-SDK arbitrator-free sentinel —
// HASH160(""), the hash160 of the empty byte string. A swap descriptor
// whose `requested_pkh` equals this value tells the engine to accept
// `OP_FALSE` instead of a signature on that leg, so any taker can settle
// the swap without the maker's signature at execute time.
//
// The dxs canonical SDK does not currently define an arbitrator-free
// sentinel — this is a Rust SDK extension surfaced here so overlays
// indexing Rust-SDK-emitted swap offers can flag them. dxs apps will not
// honor this flag at settlement time.
const EmptyHash160Hex = "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"

// IsArbitratorFreeDescriptor returns true when the descriptor's
// RequestedPkh equals the Rust SDK arbitrator-free sentinel
// `HASH160("")`. See [EmptyHash160Hex] for the cross-SDK status note.
func IsArbitratorFreeDescriptor(d *SwapDescriptor) bool {
	return d != nil && d.RequestedPkh == EmptyHash160Hex
}
